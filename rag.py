import json
from typing import List, Dict, Any
from elastic_utils import get_elasticsearch_client
from ollama_utils import OllamaClient
from config import INDEX_NAME
from prompt import (
    EXTRACT_SEMANTICS_PROMPT,
    ANALYZE_VULNERABILITY_PROMPT,
    JUDGE_VULNERABILITY_PROMPT,
    DIRECT_ANALYSIS_PROMPT,
    get_reference_info
)

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

    def extract_functional_semantics(self, code_snippet: str) -> Dict[str, str]:
        """1단계: 코드에서 기능적 의미를 추출"""
        print("\n1st step: extract functional semantics")
        prompt = EXTRACT_SEMANTICS_PROMPT.format(code=code_snippet)
        
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

        # Elasticsearch 검색 쿼리 구조
        body = {
            "query": {
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": "30%"
                }
            },
            "_source": ["metadata.functional_semantics", "metadata.vulnerability_causes", "metadata.fixing_solutions", "metadata.cve_id"]
        }
        
        try:
            response = self.es_client.search(index=INDEX_NAME, body=body, size=10) # 상위 10개 후보 추출
            hits = response["hits"]["hits"]
            print(f"\nBM25 search found {len(hits)} candidates.")
            
            # 유사도 점수와 함께 결과 출력
            print("\nSimilarity Scores:")
            for hit in hits:
                score = hit["_score"]
                cve_id = hit["_source"]["metadata"].get("cve_id", "Unknown CVE")
                print(f"- {cve_id}: {score:.2f}")
            
            return hits
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

    def extract_vulnerable_code(self, code_snippet: str, rag_data: Dict = None) -> Dict[str, Any]:
        """코드에서 취약한 부분을 추출하고 분석"""
        print("\nExtracting vulnerable code parts...")
        
        reference_info = get_reference_info(rag_data)
        prompt = ANALYZE_VULNERABILITY_PROMPT.format(
            code=code_snippet,
            reference_info=reference_info
        )
        
        try:
            response_text = self.ollama_client.generate_completion(prompt)
            start_idx = response_text.find("{")
            end_idx = response_text.rfind("}") + 1
            if start_idx != -1 and end_idx > start_idx:
                json_str = response_text[start_idx:end_idx]
                result = json.loads(json_str)
                
                if result.get("vulnerable_code"):
                    print("\nVulnerable parts found:")
                    print("-" * 50)
                    
                    # 먼저 취약점 정보 출력
                    print(f"Risk Level: {result['risk_level']}")
                    print(f"Vulnerability Type: {result['vulnerability_type']}")
                    if result.get('patch_description'):
                        print(f"\nPatch Description: {result['patch_description']}")
                    
                    # 각 취약한 부분에 대한 상세 정보
                    for part in result["vulnerable_code"]:
                        print(f"\nReason: {part['reason']}")
                        
                        # 필요한 변경사항 출력
                        if part.get('required_changes'):
                            print("\nRequired Changes:")
                            for change in part['required_changes']:
                                print(f"- Type: {change['type']}")
                                print(f"  Content: {change['content']}")
                                print(f"  Reason: {change['reason']}")
                        
                        # 추가된 라인 정보 출력
                        if part.get('added_lines'):
                            print("\nAdded Lines:")
                            for added in part['added_lines']:
                                print(f"+ {added['line']}")
                                print(f"  Purpose: {added['purpose']}")
                        
                        # 삭제된 라인 정보 출력
                        if part.get('deleted_lines'):
                            print("\nDeleted Lines:")
                            for deleted in part['deleted_lines']:
                                print(f"- {deleted['line']}")
                                print(f"  Reason: {deleted['reason']}")
                        
                        # 마지막에 코드 변경사항 출력
                        print("\nCode Changes:")
                        print(f"Lines {part['line_start']}-{part['line_end']}:")
                        
                        # 취약한 코드 부분 출력 (주변 코드 포함)
                        code_lines = code_snippet.split('\n')
                        context_lines = 2  # 취약한 부분 전후로 보여줄 라인 수
                        start_line = max(0, part['line_start'] - context_lines - 1)
                        end_line = min(len(code_lines), part['line_end'] + context_lines)
                        
                        print("\nCode context:")
                        for i in range(start_line, end_line):
                            line_marker = ">" if i + 1 >= part['line_start'] and i + 1 <= part['line_end'] else " "
                            print(f"{line_marker} {i+1:3d}| {code_lines[i]}")
                        
                        print("\nPatch Before:")
                        print(f"```\n{part['patch_before']}\n```")
                        
                        print("\nPatch After:")
                        print(f"```\n{part['patched']}\n```")
                    
                    print("-" * 50)
                else:
                    print("\nNo specific vulnerable code parts identified.")
                
                return result
            raise ValueError("Valid JSON not found in response")
        except (json.JSONDecodeError, ValueError) as e:
            print(f"Error extracting vulnerable code: {e}")
            print("Raw response:", response_text)
            return {
                "vulnerable_code": [],
                "risk_level": "unknown",
                "vulnerability_type": "unknown"
            }

    def judge_vulnerability(self, code_snippet: str, knowledge_item: Dict[str, Any]) -> Dict[str, Any]:
        """취약점 최종 판단"""
        print(f"\nJudging vulnerability against knowledge: {knowledge_item.get('cve_id', 'Unknown')}")
        
        prompt = JUDGE_VULNERABILITY_PROMPT.format(
            code=code_snippet,
            cve_id=knowledge_item.get('cve_id', 'Unknown'),
            vulnerability_causes=json.dumps(knowledge_item.get('vulnerability_causes', {}), indent=2),
            patch_info=json.dumps(knowledge_item.get('patch_info', {}), indent=2)
        )
        
        try:
            response_text = self.ollama_client.generate_completion(prompt)
            start_idx = response_text.find("{")
            end_idx = response_text.rfind("}") + 1
            if start_idx != -1 and end_idx > start_idx:
                json_str = response_text[start_idx:end_idx]
                result = json.loads(json_str)
                return result
            raise ValueError("Valid JSON not found in judge response.")
        except (json.JSONDecodeError, ValueError) as e:
            print(f"Error parsing judge response: {e}")
            print("Raw response:", response_text)
            return {"is_vulnerable": False, "explanation": "Failed to get a valid judgment from LLM."}

    def _direct_vulnerability_analysis(self, code_snippet: str) -> Dict[str, Any]:
        """RAG 비활성화 시 LLM을 이용한 직접 취약점 분석"""
        print("\nPerforming direct vulnerability analysis using LLM...")
        prompt = DIRECT_ANALYSIS_PROMPT.format(code=code_snippet)
        
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
        print("\n\n\n\n\n")
        print("="*50)
        print("vulnerability detection process started")
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
                # RAG 데이터 없이 취약한 코드 추출
                vulnerable_parts = self.extract_vulnerable_code(code_snippet)
                return {
                    "status": "analyzed_without_rag",
                    "details": vulnerable_parts
                }
            
            # 2단계(b): 후보 재정렬 (RRF)
            reranked_candidates = self.rerank_with_rrf(candidates, functional_semantics)
            
            # 3단계: 최종 판단
            print("\nFinal step: Judge vulnerability based on top candidates")
            for candidate_hit in reranked_candidates:
                knowledge_item = candidate_hit["_source"].get("metadata", {})
                
                # 취약한 코드 부분 추출
                vulnerable_parts = self.extract_vulnerable_code(code_snippet, knowledge_item)
                
                result = self.judge_vulnerability(code_snippet, knowledge_item)
                if result.get("is_vulnerable"):
                    result.update({
                        "vulnerable_parts": vulnerable_parts,
                        "fixing_solution": knowledge_item.get("fixing_solutions", {}).get("solution_description", "No solution available")
                    })
                    return {"status": "vulnerable", "details": result}
        else:
            # RAG 비활성화 시 직접 분석
            print("(RAG is disabled - using direct LLM analysis)")
            result = self._direct_vulnerability_analysis(code_snippet)
            if result.get("is_vulnerable"):
                # RAG 데이터 없이 취약한 코드 추출
                vulnerable_parts = self.extract_vulnerable_code(code_snippet)
                result["vulnerable_parts"] = vulnerable_parts
                return {"status": "vulnerable", "details": result}
        
        # 취약점이 발견되지 않은 경우에도 취약한 코드 분석 결과 포함
        vulnerable_parts = self.extract_vulnerable_code(code_snippet)
        return {
            "status": "not_vulnerable",
            "details": {
                "vulnerable_parts": vulnerable_parts
            }
        }