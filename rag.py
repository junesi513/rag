import json
from typing import List, Dict, Any
from elastic_utils import get_elasticsearch_client
from ollama_utils import OllamaClient
from config import INDEX_NAME

# 가정: ollama_utils와 elastic_utils, config는 이미 올바르게 설정되어 있음

class VulRAG:
    """
    Retrieval-Augmented Generation (RAG)을 이용한 취약점 분석 클래스.
    1. 코드의 기능적 의미 추출 (LLM)
    2. 의미 기반으로 유사 취약점 검색 (BM25)
    3. 검색된 후보들을 재정렬 (RRF)
    4. 정제된 정보 기반으로 최종 취약점 판단 (LLM)
    """
    def __init__(self, enable_rag: bool = True):
        self.enable_rag = enable_rag
        if enable_rag:
            self.es_client = get_elasticsearch_client()
        self.ollama_client = OllamaClient()

    def _get_prompt(self, prompt_type: str, **kwargs) -> str:
        """프롬프트를 중앙에서 관리하는 헬퍼 함수"""
        prompts = {
            "extract_semantics": f"""You are a code analysis system. Your task is to analyze the given code and extract its functional semantics.

IMPORTANT INSTRUCTIONS:
1. You MUST respond with ONLY a JSON object.
2. DO NOT include any text, thoughts, or explanations outside the JSON object.
3. DO NOT use markdown formatting (```json).
4. DO NOT use any XML-like tags (<think>, etc.).
5. The JSON object MUST follow this exact format:
{{
    "purpose": "Function purpose: [main purpose]",
    "behavior": "The functions of the code snippet are:\\n1. [first behavior]\\n2. [second behavior]\\n..."
}}

[Code to analyze]
{kwargs.get('code_snippet', '')}""",

            "judge_vulnerability": f"""You are a vulnerability detection system. Your task is to analyze the given code and determine if it contains a similar vulnerability pattern to a known vulnerability.

IMPORTANT INSTRUCTIONS:
1. You MUST respond with ONLY a JSON object.
2. DO NOT include any text, thoughts, or explanations outside the JSON object.
3. DO NOT use markdown formatting (```json).
4. DO NOT use any XML-like tags (<think>, etc.).
5. The JSON object MUST follow this exact format:
{{
    "is_vulnerable": true/false,
    "explanation": "Detailed explanation of why the code is vulnerable or not vulnerable",
    "severity": "high/medium/low",
    "recommendation": "Specific recommendations to fix the vulnerability if it exists, referencing the patch information if available",
    "vulnerability_id": "CVE ID of the known vulnerability"
}}

[Code to analyze]
{kwargs.get('code_snippet', '')}

[Known vulnerability information]
CVE ID: {kwargs.get('cve_id', "Unknown")}
Vulnerability causes:
- Abstract: {kwargs.get('abstract_cause', "Unknown")}
- Detailed: {kwargs.get('detailed_cause', "Unknown")}

[Patch Information]
{json.dumps(kwargs.get('patch_info', {}), indent=2)}""",

            "direct_analysis": f"""You are a vulnerability detection system. Your task is to analyze the provided code snippet directly and identify any potential security vulnerabilities.

IMPORTANT INSTRUCTIONS:
1. You MUST respond with ONLY a JSON object.
2. DO NOT include any text, thoughts, or explanations outside the JSON object.
3. DO NOT use markdown formatting (```json).
4. DO NOT use any XML-like tags (<think>, etc.).
5. The JSON object MUST follow this exact format:
{{
    "is_vulnerable": true/false,
    "explanation": "Detailed explanation of why the code is vulnerable or not. If not, state that no obvious vulnerabilities were found.",
    "severity": "high/medium/low/none",
    "recommendation": "Specific recommendations to fix the vulnerability if it exists.",
    "vulnerability_id": "N/A (Direct Analysis)"
}}

[Code to analyze]
{kwargs.get('code_snippet', '')}"""
        }
        return prompts.get(prompt_type, "")

    def extract_functional_semantics(self, code_snippet: str) -> Dict[str, str]:
        """1단계: 코드에서 기능적 의미를 추출"""
        print("\n1st step: extract functional semantics")
        prompt = self._get_prompt("extract_semantics", code_snippet=code_snippet)
        
        print("Sending code to LLM for analysis...")
        response_text = self.ollama_client.generate_completion(prompt)
        print("\nLLM Response Received.")

        try:
            start_idx = response_text.find("{")
            end_idx = response_text.rfind("}") + 1
            if start_idx != -1 and end_idx > start_idx:
                json_str = response_text[start_idx:end_idx]
                result = json.loads(json_str)
                if isinstance(result, dict) and "purpose" in result and "behavior" in result:
                    print("\nextracted functional semantics:")
                    print(json.dumps(result, indent=2, ensure_ascii=False))
                    return result
            raise ValueError("Valid JSON with required fields not found in response.")
        except (json.JSONDecodeError, ValueError) as e:
            print(f"\nError processing LLM response: {e}")
            print("Raw response:", response_text)
            return {"purpose": "Unknown", "behavior": "Unknown"}

    def bm25_search(self, functional_semantics: Dict[str, str]) -> List[Dict[str, Any]]:
        """2단계(a): BM25를 이용한 초기 검색"""
        print("\nPerforming BM25 search...")
        
        should_clauses = []
        # 'purpose'와 'behavior' 텍스트에서 키워드를 추출하여 검색 쿼리 구성
        for field, boost in [("purpose", 2.0), ("behavior", 1.0)]:
            if text := functional_semantics.get(field):
                keywords = [word for word in text.lower().split() if len(word) > 3]
                for keyword in keywords:
                    should_clauses.append({
                        "match": {
                            f"metadata.functional_semantics.{field}": {
                                "query": keyword, "boost": boost, "fuzziness": "AUTO"
                            }
                        }
                    })

        if not should_clauses:
            print("No keywords to search.")
            return []

        # 올바른 Elasticsearch 검색 쿼리 구조
        body = {
            "query": {
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": "30%"
                }
            }
        }
        
        try:
            response = self.es_client.search(index=INDEX_NAME, body=body, size=10) # 상위 10개 후보 추출
            print(f"BM25 search found {len(response['hits']['hits'])} candidates.")
            return response["hits"]["hits"]
        except Exception as e:
            print(f"Error during BM25 search: {e}")
            return []
    
    # RRF 및 유사도 계산 헬퍼 함수들 (기존 코드 유지 또는 개선)
    def calculate_cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """코사인 유사도 계산"""
        if not vec1 or not vec2: return 0.0
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = sum(a * a for a in vec1) ** 0.5
        norm2 = sum(b * b for b in vec2) ** 0.5
        if norm1 == 0 or norm2 == 0: return 0.0
        return dot_product / (norm1 * norm2)

    def calculate_text_similarity(self, text1: str, text2: str) -> float:
        """텍스트 임베딩 후 코사인 유사도 계산"""
        embedding1 = self.ollama_client.generate_embedding(text1)
        embedding2 = self.ollama_client.generate_embedding(text2)
        return self.calculate_cosine_similarity(embedding1, embedding2)

    def calculate_rrf_score(self, ranks: List[int], k: int = 60) -> float:
        """RRF 점수 계산"""
        return sum(1 / (k + r) for r in ranks)

    def rerank_with_rrf(self, candidates: List[Dict], query_semantics: Dict[str, str]) -> List[Dict[str, Any]]:
        """2단계(b): RRF를 이용한 재정렬"""
        print("\nPerforming RRF re-ranking on candidates...")
        if not candidates: return []

        reranked_results = []
        # 쿼리의 의미론적 임베딩을 미리 계산하여 효율성 증대
        query_purpose_embedding = self.ollama_client.generate_embedding(query_semantics.get("purpose", ""))
        query_behavior_embedding = self.ollama_client.generate_embedding(query_semantics.get("behavior", ""))

        # 각 후보에 대해 유사도 기반 순위 계산 및 RRF 점수 부여
        # (실제 구현에서는 이 부분을 더 정교하게 만들어야 함)
        # 여기서는 BM25 점수를 기반으로 한 간단한 예시를 보여줍니다.
        # 실제 RRF는 여러 소스(BM25, 의미유사도 등)의 순위를 조합해야 합니다.
        # 이 예제에서는 BM25 결과만 있으므로, 점수 순서대로 반환합니다.
        # 더 정교한 RRF 로직을 구현하려면 아래 주석처리된 코드를 참고하여 확장해야 합니다.

        """
        # 정교한 RRF 구현 예시 (각 후보마다 추가적인 유사도 계산 필요)
        for rank, candidate in enumerate(candidates, 1):
            source = candidate["_source"]
            # ... candidate의 purpose, behavior, keywords 등 추출 ...
            
            # 각 측면별 유사도 계산 (API 호출 필요)
            # purpose_sim = self.calculate_cosine_similarity(query_purpose_embedding, candidate_purpose_embedding)
            # behavior_sim = self.calculate_cosine_similarity(query_behavior_embedding, candidate_behavior_embedding)

            # 유사도 점수를 순위로 변환
            # ranks = [bm25_rank, purpose_rank, behavior_rank]
            
            # rrf_score = self.calculate_rrf_score(ranks)
            # candidate['rrf_score'] = rrf_score
        """
        
        # 현재는 BM25 점수만 있으므로, 그대로 정렬하여 반환
        candidates.sort(key=lambda x: x["_score"], reverse=True)
        print("Re-ranking completed (using BM25 score as proxy).")
        return candidates[:3] # 상위 3개 반환

    def judge_vulnerability(self, code_snippet: str, knowledge_item: Dict[str, Any]) -> Dict[str, Any]:
        """3단계: 정제된 지식 기반으로 취약점 최종 판단"""
        cve_id = knowledge_item.get("cve_id", "Unknown")
        print(f"\nJudging vulnerability against knowledge: {cve_id}")
        
        prompt = self._get_prompt(
            "judge_vulnerability",
            code_snippet=code_snippet,
            cve_id=cve_id,
            abstract_cause=knowledge_item.get("vulnerability_causes", {}).get("abstract_description"),
            detailed_cause=knowledge_item.get("vulnerability_causes", {}).get("detailed_description"),
            patch_info=knowledge_item.get("patch_info", {})
        )
        
        try:
            response_text = self.ollama_client.generate_completion(prompt)
            start_idx = response_text.find("{")
            end_idx = response_text.rfind("}") + 1
            if start_idx != -1 and end_idx > start_idx:
                json_str = response_text[start_idx:end_idx]
                result = json.loads(json_str)
                result['vulnerability_id'] = cve_id # 결과에 CVE ID 추가
                return result
            raise ValueError("Valid JSON not found in judge response.")
        except (json.JSONDecodeError, ValueError) as e:
            print(f"Error parsing judge response for {cve_id}: {e}")
            print("Raw response:", response_text)
            return {"is_vulnerable": False, "explanation": "Failed to get a valid judgment from LLM."}

    def _direct_vulnerability_analysis(self, code_snippet: str) -> Dict[str, Any]:
        """RAG 비활성화 시 LLM을 이용한 직접 취약점 분석"""
        print("\nPerforming direct vulnerability analysis using LLM...")
        prompt = self._get_prompt("direct_analysis", code_snippet=code_snippet)
        
        try:
            response_text = self.ollama_client.generate_completion(prompt)
            start_idx = response_text.find("{")
            end_idx = response_text.rfind("}") + 1
            if start_idx != -1 and end_idx > start_idx:
                json_str = response_text[start_idx:end_idx]
                return json.loads(json_str)
            raise ValueError("Valid JSON not found in direct analysis response.")
        except (json.JSONDecodeError, ValueError) as e:
            print(f"Error parsing direct analysis response: {e}")
            print("Raw response:", response_text)
            return {"is_vulnerable": False, "explanation": "Failed to get a valid analysis from LLM."}


    def detect_vulnerabilities(self, code_snippet: str) -> Dict[str, Any]:
        """전체 취약점 탐지 프로세스 실행"""
        print("="*50)
        print("VUL-RAG vulnerability detection process started")
        print("="*50)
        
        if self.enable_rag:
            # 1단계: 기능적 의미 추출
            functional_semantics = self.extract_functional_semantics(code_snippet)
            if functional_semantics.get("purpose") == "Unknown":
                return {"status": "error", "details": "Failed to extract functional semantics."}

            # 2단계(a): 초기 후보 검색
            candidates = self.bm25_search(functional_semantics)
            if not candidates:
                print("\nNo similar known vulnerabilities found in the initial search.")
                return {"status": "not_vulnerable", "details": "No relevant knowledge found."}
            
            # 2단계(b): 후보 재정렬 (RRF)
            reranked_candidates = self.rerank_with_rrf(candidates, functional_semantics)
            
            # 3단계: 최종 판단
            print("\nFinal step: Judge vulnerability based on top candidates")
            for candidate_hit in reranked_candidates:
                # DB에서 가져온 원본 source 데이터 사용
                knowledge_item = candidate_hit["_source"].get("metadata", {})
                
                result = self.judge_vulnerability(code_snippet, knowledge_item)
                if result.get("is_vulnerable"):
                    return {"status": "vulnerable", "details": result}
        else:
            # RAG 비활성화 시 직접 분석
            print("(RAG is disabled - using direct LLM analysis)")
            result = self._direct_vulnerability_analysis(code_snippet)
            if result.get("is_vulnerable"):
                return {"status": "vulnerable", "details": result}
        
        return {"status": "not_vulnerable", "details": None}