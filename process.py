# process.py (수정)

import json
from rag import VulRAG
from typing import Dict, Any

class VulnerabilityProcessor:
    def __init__(self, enable_rag: bool = True):
        self.rag_system = VulRAG(enable_rag=enable_rag)
        self.enable_rag = enable_rag

    def run_analysis_pipeline(self, code_snippet: str) -> Dict[str, Any]:
        """
        [의미 추출 -> 분석 -> 패치 생성] 파이프라인.
        의미 추출 실패 시, 해당 결과를 출력하고 프로세스를 중단합니다.
        """
        print("\n\n" + "="*50 + "\nAnalysis Process Started (with Semantic Extraction Check)\n" + "="*50)
        
        # --- Step 0: 의미 추출 시도 ---
        functional_semantics = self.rag_system.extract_functional_semantics(code_snippet)

        # --- 추가된 로직: 의미 추출 실패 시 프로세스 중단 ---
        if functional_semantics and functional_semantics.get("purpose") == "Unknown":
            print("\n--- SEMANTIC EXTRACTION FAILED: Process stopped. ---")
            
            final_report = {
                "status": "semantic_extraction_failed",
                "details": {
                    "message": "Failed to extract functional semantics from the code.",
                    "extraction_result": functional_semantics
                }
            }

            # 최종 보고서를 바로 출력하고 종료
            print("\n==================== FINAL REPORT ====================")
            print(json.dumps(final_report, indent=4, ensure_ascii=False))
            print("======================================================")
            return final_report
        # --- 여기까지 추가된 로직 ---


        # --- 이하 로직은 의미 추출 성공 시에만 실행됩니다. ---
        print(">>> Semantic extraction successful. Proceeding to next step.")
        
        rag_context = None
        if self.enable_rag:
            # --- Step 1: RAG 검색 ---
            # 이제 성공이 보장된 의미 정보로 검색 쿼리 생성
            purpose = functional_semantics.get("purpose", "")
            behavior_text = " ".join(functional_semantics.get("behavior", []))
            search_query = f"{purpose} {behavior_text}"
            
            print(f">>> RAG search query based on: Extracted Semantics")
            candidates = self.rag_system.bm25_search(search_query)

            if candidates:
                reranked_candidates = self.rag_system.rerank_with_rrf(candidates)
                rag_context = reranked_candidates[0].get("_source", {}).get("metadata", {})
                print(f"\n--- RAG Mode: Analyzing based on the TOP candidate ---")
            else:
                print("\n--- RAG Mode: No candidates found, switching to Direct Analysis ---")
        else:
            print("\n--- RAG Disabled: Running in Direct Analysis Mode ---")

        # --- Step 2: 통합된 분석 및 JSON 생성 ---
        analysis_result = self.rag_system.analyze_and_get_json(code_snippet, rag_context, functional_semantics)

        # --- Step 3: 결과 확인 및 패치 생성 ---
        if not analysis_result or not analysis_result.get("vulnerable_sections"):
            print("\n--- FINAL CONCLUSION: NOT VULNERABLE ---")
            print(f"Analysis Result: {json.dumps(analysis_result, indent=2, ensure_ascii=False)}")
            return {"status": "not_vulnerable", "details": analysis_result or "Analysis failed to produce a result."}

        print("\n--- VULNERABILITY CONFIRMED ---")
        print(json.dumps(analysis_result, indent=2, ensure_ascii=False))

        if self.enable_rag:
            repair_plan = self.rag_system.rag_generate_repair_plan(code_snippet, analysis_result)
            final_result_details = {
                "analysis": analysis_result,
                "repair_plan": repair_plan
            }
            print("\n--- REPAIR PLAN GENERATED ---")
            return {"status": "vulnerable_and_plan_generated", "details": final_result_details}
        else:
            patch = self.rag_system.direct_generate_patch(code_snippet, analysis_result)
            final_result_details = {
                "analysis": analysis_result,
                "patch": patch
            }
            print("\n--- PATCH GENERATED ---")
            return {"status": "vulnerable_and_patch_generated", "details": final_result_details}