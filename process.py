# process.py

import json
from rag import VulRAG
from typing import Dict, Any

class VulnerabilityProcessor:
    def __init__(self, enable_rag: bool = True):
        """
        VulRAG의 핵심 기능을 사용하여 전체 취약점 분석 프로세스를 조율합니다.
        """
        self.rag_system = VulRAG(enable_rag=enable_rag)
        self.enable_rag = enable_rag

    def run_analysis_pipeline(self, code_snippet: str) -> Dict[str, Any]:
        """
        전체 취약점 탐지 및 분석 파이프라인을 실행합니다.
        """
        print("\n\n" + "="*50 + "\nVulnerability Detection Process Started\n" + "="*50)
        
        # 1단계: 기능적 의미 추출
        functional_semantics = self.rag_system.extract_functional_semantics(code_snippet)
        if self.enable_rag and functional_semantics.get("purpose") == "Unknown":
            return {"status": "error", "details": "Failed to extract functional semantics."}

        if self.enable_rag:
            # 2단계: 후보 검색
            candidates = self.rag_system.bm25_search(functional_semantics)
            
            # --- 유사도 점수 100점 기준 분기 로직 ---
            if not candidates or candidates[0].get("_score", 0) < 100:
                print("\nSimilarity score is below the threshold (100) or no candidates found.")
                print("Switching to direct LLM analysis mode.")
                
                # LLM 직접 분석 수행
                direct_analysis_result = self.rag_system.direct_vulnerability_analysis(code_snippet)
                
                # 직접 분석 결과에 따라 수리 제안 생성
                if direct_analysis_result.get("is_vulnerable"):
                    # 직접 분석 결과는 상세 정보가 부족하므로, 수리를 위해 다시 상세 분석을 요청
                    analysis_for_repair = self.rag_system.analyze_vulnerability(code_snippet, None, functional_semantics)
                    repair_suggestions = self.rag_system.generate_repair_suggestions(analysis_for_repair)
                    
                    final_result = {
                        "judgment": direct_analysis_result,
                        "analysis": analysis_for_repair,
                        "repair_suggestions": repair_suggestions
                    }
                    return {"status": "vulnerable_direct_analysis", "details": final_result}
                else:
                    return {"status": "not_vulnerable_direct_analysis", "details": direct_analysis_result}
            
            # --- 100점 이상일 경우, 기존 RAG 파이프라인 계속 진행 ---
            reranked_candidates = self.rag_system.rerank_with_rrf(candidates)
            
            # 3단계: 최종 판단
            print("\nFinal step: Judge vulnerability based on top candidates")
            for candidate_hit in reranked_candidates:
                knowledge_item = candidate_hit.get("_source", {}).get("metadata", {})
                
                # 컨텍스트 체이닝
                analysis_result = self.rag_system.analyze_vulnerability(code_snippet, knowledge_item, functional_semantics)
                final_judgment = self.rag_system.judge_vulnerability(code_snippet, knowledge_item, analysis_result)
                
                if final_judgment.get("is_vulnerable"):
                    # 취약점이 확인된 경우에만 수리 제안 생성
                    repair_suggestions = self.rag_system.generate_repair_suggestions(analysis_result)
                    
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
                         print("\n--- Repair Candidates ---")
                         for i, candidate in enumerate(repair_suggestions.get("repair_suggestions", []), 1):
                             print(f"\n[Candidate #{i} for Line {candidate.get('line_number', '?')}]")
                             print(f"  - Original: {candidate.get('original_content', 'N/A')}")
                             print(f"  + Modified: {candidate.get('suggested_modification', 'N/A')}")
                             print(f"  Reason: {candidate.get('reason_for_change', 'N/A')}")
                    
                    print("---------------------------------")
                    return {"status": "vulnerable", "details": final_result}
        else: # RAG가 비활성화된 경우
             print("\nRAG is disabled. Switching to direct LLM analysis mode.")
             direct_analysis_result = self.rag_system.direct_vulnerability_analysis(code_snippet)
             
             if direct_analysis_result.get("is_vulnerable"):
                 # 직접 분석 결과는 상세 정보가 부족하므로, 수리를 위해 다시 상세 분석을 요청
                 analysis_for_repair = self.rag_system.analyze_vulnerability(code_snippet, None, functional_semantics)
                 repair_suggestions = self.rag_system.generate_repair_suggestions(analysis_for_repair)
                 
                 final_result = {
                     "judgment": direct_analysis_result,
                     "analysis": analysis_for_repair,
                     "repair_suggestions": repair_suggestions
                 }

                 if repair_suggestions.get("repair_suggestions"):
                    print("\n--- Repair Candidates (Direct Analysis) ---")
                    for i, candidate in enumerate(repair_suggestions.get("repair_suggestions", []), 1):
                        print(f"\n[Candidate #{i} for Line {candidate.get('line_number', '?')}]")
                        print(f"  - Original: {candidate.get('original_content', 'N/A')}")
                        print(f"  + Modified: {candidate.get('suggested_modification', 'N/A')}")
                        print(f"  Reason: {candidate.get('reason_for_change', 'N/A')}")

                 return {"status": "vulnerable_direct_analysis", "details": final_result}
             else:
                 return {"status": "not_vulnerable_direct_analysis", "details": direct_analysis_result}

        print("\n--- FINAL CONCLUSION: NOT VULNERABLE ---")
        return {"status": "not_vulnerable", "details": "No vulnerabilities were confirmed based on the provided knowledge base."}
