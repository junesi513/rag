# rag.py (최종 버전)
import json
import re
from typing import List, Dict, Any
from elastic_utils import get_elasticsearch_client
from ollama_utils import OllamaClient
from config import INDEX_NAME
from prompt import (
    EXTRACT_SEMANTICS_PROMPT,
    RAG_ANALYZE_JSON_PROMPT,
    DIRECT_ANALYZE_JSON_PROMPT,
    RAG_GENERATE_REPAIR_PLAN_PROMPT,
    DIRECT_GENERATE_PATCH_PROMPT
)

class VulRAG:
    def __init__(self, enable_rag: bool = True):
        self.enable_rag = enable_rag
        if enable_rag:
            self.es_client = get_elasticsearch_client()
        self.ollama_client = OllamaClient()

    def _generate_and_clean(self, prompt: str) -> str:
        raw_response = self.ollama_client.generate_completion(prompt)
        cleaned_response = re.sub(r'<think>.*?</think>', '', raw_response, flags=re.DOTALL).strip()
        return cleaned_response

    def _parse_llm_response(self, response_text: str) -> Dict:
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

    def extract_functional_semantics(self, code_snippet: str) -> Dict[str, str]:
        """[Step 0: 기능적 의미 추출] 코드의 목적과 동작을 분석합니다."""
        print("\nExecuting: Step 0 - Extract Functional Semantics")
        prompt = EXTRACT_SEMANTICS_PROMPT.format(code=code_snippet)
        response_text = self._generate_and_clean(prompt)
        result = self._parse_llm_response(response_text)
        # 실패 시 기본값 반환
        if "purpose" not in result or "behavior" not in result:
             return {"purpose": "Unknown", "behavior": "Unknown"}
        return result

    def bm25_search(self, query_text: str) -> List[Dict[str, Any]]:
        print("\nExecuting: RAG Search (BM25)")
        if not query_text: return []
        body = {
            "query": {
                "match": {
                    "metadata.vulnerability_causes.abstract_description": {
                        "query": query_text,
                        "fuzziness": "AUTO"
                    }
                }
            }
        }
        try:
            response = self.es_client.search(index=INDEX_NAME, body=body, size=10)
            return response["hits"]["hits"]
        except Exception as e:
            print(f"Error during BM25 search: {e}")
            return []

    def rerank_with_rrf(self, candidates: List[Dict]) -> List[Dict[str, Any]]:
        print("\nExecuting: Reranking Candidates")
        if not candidates: return []
        candidates.sort(key=lambda x: x.get("_score", 0), reverse=True)
        return candidates[:1]

    def analyze_and_get_json(self, code_snippet: str, rag_data: Dict = None) -> Dict[str, Any]:
        """[Step 1: 통합된 분석 및 JSON 생성] RAG/Direct 모드에 따라 적절한 프롬프트를 사용하여 분석을 수행하고 JSON을 반환합니다."""
        print("\nExecuting: Step 1 - Integrated Analysis & JSON Generation")
        
        if self.enable_rag and rag_data:
            print("Using RAG-context-based analysis prompt.")
            reference_info = json.dumps(rag_data.get('vulnerability_causes', {}), indent=2)
            prompt = RAG_ANALYZE_JSON_PROMPT.format(
                code=code_snippet, reference_info=reference_info
            )
        else:
            print("Using Direct-mode-specific analysis prompt.")
            prompt = DIRECT_ANALYZE_JSON_PROMPT.format(code=code_snippet)
            
        response_text = self._generate_and_clean(prompt)
        return self._parse_llm_response(response_text)

    # --- 아래 두 개의 메소드가 모두 정의되어 있는지 확인하세요 ---
    def rag_generate_repair_plan(self, original_code: str, analysis: Dict) -> Dict:
        """[Step 2 - RAG Mode] RAG 분석 결과를 바탕으로 Insert/Update/Delete 수리 계획을 생성합니다."""
        print("\nExecuting: Step 2 - Generate Repair Plan (RAG Mode)")
        prompt = RAG_GENERATE_REPAIR_PLAN_PROMPT.format(
            original_code=original_code,
            analysis_json=json.dumps(analysis, indent=2)
        )
        response_text = self._generate_and_clean(prompt)
        return self._parse_llm_response(response_text)

    def direct_generate_patch(self, original_code: str, analysis: Dict) -> Dict:
        """[Step 2 - Direct Mode] 분석 결과를 바탕으로 단일 패치 코드를 생성합니다."""
        print("\nExecuting: Step 2 - Generate Single Patch (Direct Mode)")
        prompt = DIRECT_GENERATE_PATCH_PROMPT.format(
            original_code=original_code,
            analysis_json=json.dumps(analysis, indent=2)
        )
        response_text = self._generate_and_clean(prompt)
        return self._parse_llm_response(response_text)