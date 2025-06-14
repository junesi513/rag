# junesi513/rag/rag-8ee72d8e489f6f6dbff76adc48d163ed2208e189/rag.py

import json
from typing import List, Dict, Any
from elastic_utils import get_elasticsearch_client
from ollama_utils import OllamaClient
from config import INDEX_NAME
from prompt import (
    EXTRACT_SEMANTICS_PROMPT,
    ANALYZE_VULNERABILITY_PROMPT,
    JUDGE_VULNERABILITY_PROMPT,
    REPAIR_PROMPT,
    get_reference_info,
    get_semantics_info,
    get_analysis_context
)

class VulRAG:
    def __init__(self, enable_rag: bool = True):
        self.enable_rag = enable_rag
        if enable_rag:
            self.es_client = get_elasticsearch_client()
        self.ollama_client = OllamaClient()

    def _parse_llm_response(self, response_text: str) -> Dict:
        """LLM 응답에서 JSON 객체를 안전하게 추출하고 파싱합니다."""
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
        """1단계: 코드에서 기능적 의미를 추출"""
        print("\n1st step: extract functional semantics")
        prompt = EXTRACT_SEMANTICS_PROMPT.format(code=code_snippet)
        response_text = self.ollama_client.generate_completion(prompt)
        result = self._parse_llm_response(response_text)
        if "purpose" not in result or "behavior" not in result:
             return {"purpose": "Unknown", "behavior": "Unknown"}
        print("\nextracted functional semantics:")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return result

    def bm25_search(self, functional_semantics: Dict[str, str]) -> List[Dict[str, Any]]:
        """2단계(a): BM25를 이용한 초기 검색"""
        print("\nPerforming BM25 search...")
        should_clauses = []
        for field, boost in [("purpose", 2.0), ("behavior", 1.0)]:
            if text := functional_semantics.get(field):
                keywords = [word for word in text.lower().split() if len(word) > 3]
                for keyword in keywords:
                    should_clauses.append({"match": {f"metadata.functional_semantics.{field}": {"query": keyword, "boost": boost, "fuzziness": "AUTO"}}})
        if not should_clauses: return []
        body = {"query": {"bool": {"should": should_clauses, "minimum_should_match": "30%"}}, "_source": ["metadata.functional_semantics", "metadata.vulnerability_causes", "metadata.fixing_solutions", "metadata.cve_id"]}
        try:
            response = self.es_client.search(index=INDEX_NAME, body=body, size=10)
            hits = response["hits"]["hits"]
            print(f"\nBM25 search found {len(hits)} candidates.")
            for hit in hits:
                print(f"- {hit.get('_source', {}).get('metadata', {}).get('cve_id', 'Unknown CVE')}: {hit.get('_score', 0):.2f}")
            return hits
        except Exception as e:
            print(f"Error during BM25 search: {e}")
            return []

    def rerank_with_rrf(self, candidates: List[Dict]) -> List[Dict[str, Any]]:
        """2단계(b): RRF를 이용한 재정렬"""
        print("\nRe-ranking candidates...")
        if not candidates: return []
        candidates.sort(key=lambda x: x.get("_score", 0), reverse=True)
        return candidates[:3]

    def analyze_vulnerability(self, code_snippet: str, rag_data: Dict = None, functional_semantics: Dict = None) -> Dict[str, Any]:
        """3단계: 취약점 상세 분석"""
        print("\nAnalyzing for potential vulnerabilities...")
        reference_info = get_reference_info(rag_data)
        semantics_info = get_semantics_info(functional_semantics)
        prompt = ANALYZE_VULNERABILITY_PROMPT.format(
            code=code_snippet, reference_info=reference_info, semantics_info=semantics_info
        )
        response_text = self.ollama_client.generate_completion(prompt)
        return self._parse_llm_response(response_text)

    def judge_vulnerability(self, code_snippet: str, knowledge_item: Dict[str, Any], detailed_analysis: Dict = None) -> Dict[str, Any]:
        """4단계: 취약점 최종 판단"""
        cve_id = knowledge_item.get('cve_id', 'Unknown')
        print(f"\nJudging vulnerability against knowledge: {cve_id}")
        analysis_context = get_analysis_context(detailed_analysis)
        prompt = JUDGE_VULNERABILITY_PROMPT.format(
            code=code_snippet,
            cve_id=cve_id,
            vulnerability_causes=json.dumps(knowledge_item.get('vulnerability_causes', {}), indent=2),
            patch_info=json.dumps(knowledge_item.get('patch_info', {}), indent=2),
            initial_analysis=analysis_context
        )
        response_text = self.ollama_client.generate_completion(prompt)
        return self._parse_llm_response(response_text)

    def generate_repair_suggestions(self, vulnerability_analysis: Dict) -> Dict:
        """5단계: 취약점 분석 결과를 바탕으로 라인별 수리 제안 생성"""
        print("\nGenerating repair suggestions...")
        if not vulnerability_analysis.get("vulnerable_sections"):
            return {}

        prompt = REPAIR_PROMPT.format(
            vulnerability_analysis_json=json.dumps(vulnerability_analysis, indent=2)
        )
        response_text = self.ollama_client.generate_completion(prompt)
        return self._parse_llm_response(response_text)

    def detect_vulnerabilities(self, code_snippet: str) -> Dict[str, Any]:
        """전체 취약점 탐지 파이프라인"""
        print("\n\n" + "="*50 + "\nVulnerability Detection Process Started\n" + "="*50)
        
        functional_semantics = self.extract_functional_semantics(code_snippet)
        if self.enable_rag and functional_semantics.get("purpose") == "Unknown":
            return {"status": "error", "details": "Failed to extract functional semantics."}

        if self.enable_rag:
            candidates = self.bm25_search(functional_semantics)
            if not candidates:
                print("\nNo similar known vulnerabilities found. Analyzing without RAG context.")
                analysis_result = self.analyze_vulnerability(code_snippet, None, functional_semantics)
                return {"status": "analyzed_without_rag", "details": analysis_result}
            
            reranked_candidates = self.rerank_with_rrf(candidates)
            
            print("\nFinal step: Judge vulnerability based on top candidates")
            for candidate_hit in reranked_candidates:
                knowledge_item = candidate_hit.get("_source", {}).get("metadata", {})
                
                analysis_result = self.analyze_vulnerability(code_snippet, knowledge_item, functional_semantics)
                final_judgment = self.judge_vulnerability(code_snippet, knowledge_item, analysis_result)
                
                if final_judgment.get("is_vulnerable"):
                    # 취약점이 확인된 경우에만 수리 제안 생성
                    repair_suggestions = self.generate_repair_suggestions(analysis_result)
                    
                    final_result = {
                        "judgment": final_judgment,
                        "analysis": analysis_result,
                        "repair_suggestions": repair_suggestions,
                    }
                    
                    # 최종 결과 출력
                    print("\n--- VULNERABILITY CONFIRMED ---")
                    print(f"Based on: {knowledge_item.get('cve_id', 'Unknown')}")
                    print(f"Severity: {final_judgment.get('severity', 'N/A')}")
                    print(f"Explanation: {final_judgment.get('explanation', 'N/A')}")
                    
                    if repair_suggestions.get("repair_suggestions"):
                         print("\n--- Suggested Repair Actions ---")
                         for suggestion in repair_suggestions.get("repair_suggestions", []):
                             print(f"\n[Line {suggestion.get('line_number', '?')}]")
                             print(f"  Reason: {suggestion.get('reason_for_change', 'N/A')}")
                             print(f"  Original: {suggestion.get('original_content', '')}")
                             print(f"  Modified: {suggestion.get('suggested_modification', '')}")
                    
                    print("---------------------------------")
                    return {"status": "vulnerable", "details": final_result}
        
        print("\n--- FINAL CONCLUSION: NOT VULNERABLE ---")
        return {"status": "not_vulnerable", "details": "No vulnerabilities were confirmed based on the provided knowledge base."}
