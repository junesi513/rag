# process.py (하이브리드 최종 버전)

import json
from rag import VulRAG # rag.py의 클래스명이 VulRAG라고 가정
from typing import Dict, Any, List

class VulnerabilityProcessor:
    def __init__(self, enable_rag: bool = True):
        # (복원) RAG 활성화 플래그를 다시 사용
        self.rag_system = VulRAG(enable_rag=enable_rag)
        self.enable_rag = enable_rag

    def run_analysis_pipeline(self, code_snippet: str) -> Dict[str, Any]:
        """
        RAG 사용 여부에 따라 동적으로 컨텍스트를 구성하고,
        [분석 -> 판단 -> 수정 계획 생성] 파이프라인을 수행합니다.
        """
        print("\n\n" + "="*50 + "\nHybrid Analysis & Repair Process Started\n" + "="*50)
        
        # --- 1. 공통 준비 단계: 기능 의미 추출 ---
        functional_semantics = self.rag_system.extract_functional_semantics(code_snippet)
        
        analysis_contexts: List[Dict | None] = []
        is_rag_mode = False
        
        # --- 2. 컨텍스트 구성 단계 (RAG 활성화 여부에 따라 분기) ---
        if self.enable_rag:
            candidates = self.rag_system.bm25_search(functional_semantics)
            if candidates:
                reranked_candidates = self.rag_system.rerank_with_rrf(candidates)
                # _source에서 metadata만 추출하여 컨텍스트로 사용
                analysis_contexts = [hit.get("_source", {}).get("metadata", {}) for hit in reranked_candidates]
                is_rag_mode = True
                print(f"\n--- RAG Mode: Analyzing based on top {len(analysis_contexts)} candidates ---")
            else:
                analysis_contexts = [None] # DB 검색 결과 없으면 Direct 모드로 전환
                print("\n--- RAG Mode: No candidates found, switching to Direct Analysis ---")
        else:
            analysis_contexts = [None] # RAG 비활성화 시 Direct 모드로 설정
            print("\n--- RAG Disabled: Running in Direct Analysis Mode ---")
            
        # --- 3. 통합된 분석 및 수리 루프 ---
        for context_item in analysis_contexts:
            analysis_result = self.rag_system.analyze_vulnerability(code_snippet, context_item, functional_semantics)
            
            final_judgment = {}
            if is_rag_mode and context_item:
                final_judgment = self.rag_system.judge_vulnerability(code_snippet, context_item, analysis_result)
            else:
                # --- Direct 모드 로직 수정 ---
                # 기존의 단순 if문 대신, 새로운 direct_judge_vulnerability 메소드를 호출합니다.
                if analysis_result.get("vulnerable_sections"):
                    final_judgment = self.rag_system.direct_judge_vulnerability(code_snippet, analysis_result)
                else:
                    final_judgment = {"is_vulnerable": False, "explanation": "No vulnerable sections found in direct analysis."}
                # --- 여기까지 수정 ---

            # 3-3. 취약점 확정 시, 수정 계획 생성 (교체된 로직)
            if final_judgment.get("is_vulnerable"):
                print("\n--- VULNERABILITY CONFIRMED ---")
                if is_rag_mode and context_item:
                    print(f"Based on: {context_item.get('cve_id', 'Unknown')}")
                print(f"Severity: {final_judgment.get('severity', 'N/A')}")
                print(f"Explanation: {final_judgment.get('explanation', 'N/A')}")
                
                # (교체) 기존의 복잡한 3단계 수리 로직을 삭제하고,
                # 새로운 '수정 계획 생성' 메소드를 한 번만 호출합니다.
                repair_plan = self.rag_system.generate_repair_plan(code_snippet, analysis_result, final_judgment)
                
                final_result_details = {
                    "judgment": final_judgment,
                    "analysis": analysis_result,
                    "repair_plan": repair_plan # (교체) 결과를 'repair_plan'으로 저장
                }
                
                print("\n--- REPAIR PLAN GENERATED ---")
                print(json.dumps(repair_plan, indent=2, ensure_ascii=False))
                print("---------------------------------")
                
                return {"status": "vulnerable_and_plan_generated", "details": final_result_details}
        
        # 루프가 모두 끝날 때까지 취약점이 발견되지 않은 경우
        print("\n--- FINAL CONCLUSION: NOT VULNERABLE ---")
        return {"status": "not_vulnerable", "details": "No vulnerabilities were confirmed by the analysis."}