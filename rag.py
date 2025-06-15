# rag.py (하이브리드 버전)

import json
import re
from typing import List, Dict, Any
from elastic_utils import get_elasticsearch_client
from ollama_utils import OllamaClient
from config import INDEX_NAME
from prompt import (
    # (복원) 분석/판단에 필요한 프롬프트들
    EXTRACT_SEMANTICS_PROMPT,
    ANALYZE_VULNERABILITY_PROMPT,
    JUDGE_VULNERABILITY_PROMPT,
    DIRECT_JUDGE_VULNERABILITY_PROMPT,
    # (신규) 새로운 수리 계획 프롬프트
    GENERATE_REPAIR_PLAN_PROMPT,
    # (복원) RAG 컨텍스트 생성을 위한 헬퍼 함수들
    get_reference_info,
    get_semantics_info,
    get_analysis_context
)

class VulRAG:
    def __init__(self, enable_rag: bool = True):
        # (복원) RAG 활성화 플래그 및 Elasticsearch 클라이언트 초기화
        self.enable_rag = enable_rag
        if enable_rag:
            self.es_client = get_elasticsearch_client()
        self.ollama_client = OllamaClient()

    # (유지) LLM 호출 및 파싱을 위한 내부 헬퍼 메소드들
    def _generate_and_clean(self, prompt: str) -> str:
        # ... (이전과 동일)
        raw_response = self.ollama_client.generate_completion(prompt)
        cleaned_response = re.sub(r'<think>.*?</think>', '', raw_response, flags=re.DOTALL).strip()
        return cleaned_response

    def _parse_llm_response(self, response_text: str) -> Dict:
        # ... (이전과 동일)
        try:
            start_idx = response_text.find("{")
            end_idx = response_text.rfind("}") + 1
            if start_idx != -1 and end_idx > start_idx:
                json_str = response_text[start_idx:end_idx]
                return json.loads(json_str)
            return {}
        except (json.JSONDecodeError, ValueError) as e:
            print(f"\nError parsing LLM response: {e}\nRaw response: {response_text}")
            return {}

    # --- (복원) 분석 및 판단을 위한 RAG 파이프라인 메소드들 ---

    def extract_functional_semantics(self, code_snippet: str) -> Dict[str, str]:
        """[1단계] 코드의 기능적 의미를 추출합니다."""
        print("\nExecuting: Step 1 - Extract Functional Semantics")
        prompt = EXTRACT_SEMANTICS_PROMPT.format(code=code_snippet)
        response_text = self._generate_and_clean(prompt)
        result = self._parse_llm_response(response_text)
        if "purpose" not in result or "behavior" not in result:
             return {"purpose": "Unknown", "behavior": "Unknown"}
        return result

    def bm25_search(self, functional_semantics: Dict[str, str]) -> List[Dict[str, Any]]:
        print("\nExecuting: RAG Search (BM25)")
        should_clauses = []
        for field, boost in [("purpose", 2.0), ("behavior", 1.0)]:
            if text := functional_semantics.get(field):
                
                # --- 여기부터 수정 ---
                search_text = ""
                if isinstance(text, list):
                    # 'text'가 리스트일 경우, 공백으로 구분된 단일 문자열로 합칩니다.
                    search_text = " ".join(str(item) for item in text)
                elif isinstance(text, str):
                    # 'text'가 문자열일 경우, 그대로 사용합니다.
                    search_text = text
                else:
                    # 그 외의 타입일 경우를 대비해 문자열로 변환합니다.
                    search_text = str(text)

                # 이제 안전하게 .lower()를 사용할 수 있습니다.
                keywords = [word for word in search_text.lower().split() if len(word) > 3]
                # --- 여기까지 수정 ---
                
                for keyword in keywords:
                    should_clauses.append({"match": {f"metadata.functional_semantics.{field}": {"query": keyword, "boost": boost, "fuzziness": "AUTO"}}})
        # ... (이후 로직은 동일) ...
        if not should_clauses: return []
        body = {"query": {"bool": {"should": should_clauses, "minimum_should_match": "30%"}}, "_source": ["metadata.functional_semantics", "metadata.vulnerability_causes", "metadata.fixing_solutions", "metadata.cve_id", "metadata.patch_info"]}
        try:
            response = self.es_client.search(index=INDEX_NAME, body=body, size=10)
            return response["hits"]["hits"]
        except Exception as e:
            print(f"Error during BM25 search: {e}")
            return []


    def rerank_with_rrf(self, candidates: List[Dict]) -> List[Dict[str, Any]]:
        """RAG: 검색된 후보군을 스코어 기반으로 재정렬합니다."""
        print("\nExecuting: Reranking Candidates")
        if not candidates: return []
        candidates.sort(key=lambda x: x.get("_score", 0), reverse=True)
        return candidates[:3]

    def analyze_vulnerability(self, code_snippet: str, rag_data: Dict = None, functional_semantics: Dict = None) -> Dict[str, Any]:
        """[2단계] RAG 정보를 참조하여 잠재적 취약점을 상세 분석합니다."""
        print("\nExecuting: Step 2 - Analyze Vulnerability (with RAG context)")
        reference_info = get_reference_info(rag_data)
        semantics_info = get_semantics_info(functional_semantics)
        prompt = ANALYZE_VULNERABILITY_PROMPT.format(
            code=code_snippet, reference_info=reference_info, semantics_info=semantics_info
        )
        response_text = self._generate_and_clean(prompt)
        return self._parse_llm_response(response_text)

    def judge_vulnerability(self, code_snippet: str, knowledge_item: Dict[str, Any], detailed_analysis: Dict = None) -> Dict[str, Any]:
        """[3단계] RAG 정보와 상세 분석을 종합해 최종 판정을 내립니다."""
        cve_id = knowledge_item.get('cve_id', 'Unknown')
        print(f"\nExecuting: Step 3 - Judge Vulnerability against {cve_id}")
        analysis_context = get_analysis_context(detailed_analysis)
        prompt = JUDGE_VULNERABILITY_PROMPT.format(
            code=code_snippet, cve_id=cve_id,
            vulnerability_causes=json.dumps(knowledge_item.get('vulnerability_causes', {}), indent=2),
            patch_info=json.dumps(knowledge_item.get('patch_info', {}), indent=2),
            initial_analysis=analysis_context
        )
        response_text = self._generate_and_clean(prompt)
        return self._parse_llm_response(response_text)

    # --- (교체) 신규 수정 계획 생성 메소드 ---
    # --- (신규 추가) Direct 모드를 위한 최종 판정 메소드 ---
    def direct_judge_vulnerability(self, code_snippet: str, detailed_analysis: Dict = None) -> Dict[str, Any]:
        """[3단계-Direct] 상세 분석 결과만으로 최종 판정을 내립니다."""
        print("\nExecuting: Step 3 - Judge Vulnerability (Direct Mode)")
        analysis_context = get_analysis_context(detailed_analysis)
        prompt = DIRECT_JUDGE_VULNERABILITY_PROMPT.format(
            code=code_snippet,
            initial_analysis=analysis_context
        )
        response_text = self._generate_and_clean(prompt)
        return self._parse_llm_response(response_text)


    def generate_repair_plan(self, original_code: str, vulnerability_analysis: Dict, final_judgment: Dict) -> Dict:
        """[4단계] 최종 판정 결과를 바탕으로 구체적인 수정 계획을 생성합니다."""
        print("\nExecuting: Step 4 - Generate Repair Plan")
        prompt = GENERATE_REPAIR_PLAN_PROMPT.format(
            original_code=original_code,
            vulnerability_analysis_json=json.dumps(vulnerability_analysis, indent=2),
            final_judgment_json=json.dumps(final_judgment, indent=2)
        )
        response_text = self._generate_and_clean(prompt)
        return self._parse_llm_response(response_text)