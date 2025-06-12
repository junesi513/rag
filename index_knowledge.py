import json
import os
from document_processor import DocumentProcessor
from ollama_utils import OllamaClient

def index_knowledge_base():
    """knowledge/data.jsonl 파일의 취약점 지식을 Elasticsearch에 인덱싱합니다."""
    
    # 파일 존재 여부 확인
    knowledge_file = "knowledge/data.jsonl"
    if not os.path.exists(knowledge_file): 
        print(f"\n오류: 지식 베이스 파일을 찾을 수 없습니다: {knowledge_file}")  
        print("파일이 올바른 위치에 있는지 확인해주세요.")
        return
    
    processor = DocumentProcessor()
    ollama_client = OllamaClient()
    
    print("취약점 지식 인덱싱 시작...")
    
    # JSONL 파일 읽기
    with open("knowledge/data.jsonl", "r", encoding="utf-8") as f:
        for line in f:
            item = json.loads(line)
            
            # 텍스트 구성
            text = f"""
            CVE ID: {list(item.keys())[1]}
            
            기능적 의미:
            - 목적: {item[list(item.keys())[1]]['file_specific_analysis'][0]['vulnerability_behavior']['functional_semantics']['purpose']}
            - 동작: {item[list(item.keys())[1]]['file_specific_analysis'][0]['vulnerability_behavior']['functional_semantics']['behavior']}
            
            취약점 원인:
            {item[list(item.keys())[1]]['file_specific_analysis'][0]['vulnerability_behavior']['vulnerability_knowledge']['vulnerability_causes']}
            
            해결 방안:
            {item[list(item.keys())[1]]['file_specific_analysis'][0]['vulnerability_behavior']['vulnerability_knowledge']['fixing_solutions']}
            """
            
            # 메타데이터 구성
            metadata = {
                "cve_id": list(item.keys())[1],
                "functional_semantics": item[list(item.keys())[1]]["file_specific_analysis"][0]["vulnerability_behavior"]["functional_semantics"],
                "vulnerability_causes": item[list(item.keys())[1]]["file_specific_analysis"][0]["vulnerability_behavior"]["vulnerability_knowledge"]["vulnerability_causes"],
                "fixing_solutions": item[list(item.keys())[1]]["file_specific_analysis"][0]["vulnerability_behavior"]["vulnerability_knowledge"]["fixing_solutions"]
            }
            
            # 문서 처리 및 인덱싱
            processor.process_and_index_text(text, metadata)
            print(f"인덱싱 완료: {list(item.keys())[1]}")
    
    print("모든 취약점 지식 인덱싱 완료!")

if __name__ == "__main__":
    index_knowledge_base() 