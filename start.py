# start.py (단일 처리 + 대량 처리 기능 통합 버전)

import json
import argparse
import sys
import os # <--- os 모듈 추가

from process import VulnerabilityProcessor

def load_code_from_json(json_path: str, id: str) -> str:
    """JSON 파일에서 특정 id의 코드를 로드합니다. (기존과 동일)"""
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if not isinstance(data, list):
            raise ValueError("JSON 파일은 배열(list) 형태여야 합니다.")
            
        target_item = next((item for item in data if str(item.get('id')) == id), None)
            
        if target_item is None:
            # 대량 처리 시 데이터가 없는 것은 에러가 아니므로 None을 반환하도록 수정
            return None
            
        files = target_item.get('files')
        if not files or not isinstance(files, list) or len(files) == 0:
            raise ValueError(f"ID '{id}': JSON 항목에 'files' 배열이 없거나 비어있습니다.")
            
        code_before = files[0].get('code_before')
        if code_before is None:
            raise ValueError(f"ID '{id}': 첫 번째 file 객체에 'code_before' 키가 없습니다.")
            
        return code_before
    except FileNotFoundError:
        raise FileNotFoundError(f"파일을 찾을 수 없습니다: {json_path}")
    except json.JSONDecodeError:
        raise ValueError(f"잘못된 JSON 형식입니다: {json_path}")
    except Exception as e:
        # 에러 메시지에 ID를 포함시켜 디버깅 용이성 향상
        raise type(e)(f"ID '{id}'의 코드를 로드하는 중 에러 발생: {e}")


def main():
    """메인 실행 함수"""
    parser = argparse.ArgumentParser(
        description='코드 취약점 분석 도구 (Code Vulnerability Analysis Tool)',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''
사용 예시:
  (단일 분석)
  1. 직접 코드 입력:
     python start.py 'public class MyClass {{ ... }}'

  2. JSON 파일에서 단일 ID 로드:
     python start.py --json-file path/to/data.json --id 1

  (대량 분석)
  3. ID 범위를 지정하여 자동 분석 및 저장 (RAG 활성화):
     python start.py --json-file path/to/data.json --id-range 1-79

  4. ID 범위를 지정하여 자동 분석 및 저장 (RAG 비활성화):
     python start.py --json-file path/to/data.json --id-range 1-79 --disable-rag
'''
    )
    
    # --- 인자(Argument) 정의 ---
    parser.add_argument('code', nargs='?', help='분석할 코드 (작은따옴표로 감싸서 입력)')
    parser.add_argument('--disable-rag', action='store_true', help='RAG 기능을 비활성화하고 LLM만 사용하여 분석')
    parser.add_argument('--json-file', help='분석할 코드가 포함된 JSON 파일 경로')
    parser.add_argument('--id', help='JSON 파일에서 로드할 단일 코드의 id')
    # 대량 처리를 위한 --id-range 인자 추가
    parser.add_argument('--id-range', help='자동으로 처리할 ID 범위 (예: "1-79")')

    args = parser.parse_args()

    # VulnerabilityProcessor 객체 생성 (모드에 상관없이 공통)
    processor = VulnerabilityProcessor(enable_rag=not args.disable_rag)

    # --- 실행 모드 분기 ---
    
    # 1. 대량 처리 모드 (id-range가 지정된 경우)
    if args.id_range:
        if not args.json_file:
            parser.error("--id-range 옵션을 사용하려면 --json-file도 반드시 지정해야 합니다.")
        if args.id or args.code:
            parser.error("--id-range 옵션은 단일 --id 또는 직접 코드 입력과 함께 사용할 수 없습니다.")

        try:
            start_id_str, end_id_str = args.id_range.split('-')
            start_id = int(start_id_str)
            end_id = int(end_id_str)
            if start_id > end_id: raise ValueError("시작 ID는 종료 ID보다 클 수 없습니다.")
        except ValueError as e:
            parser.error(f"잘못된 ID 범위 형식입니다. '시작-끝' 형태로 입력하세요. (예: '1-79'). 상세: {e}")

        result_base_dir = "./result/RAG" if not args.disable_rag else "./result/No-RAG"
        os.makedirs(result_base_dir, exist_ok=True)
        
        print(f"대량 분석 모드를 시작합니다. (ID: {start_id}~{end_id})")
        print(f"결과 저장 위치: {result_base_dir}")
        print("-" * 50)

        for current_id in range(start_id, end_id + 1):
            try:
                print(f"\n{'='*20} ID: {current_id} 처리 시작 {'='*20}")
                code_snippet = load_code_from_json(args.json_file, str(current_id))
                
                if code_snippet is None:
                    print(f"--- ID: {current_id} 데이터를 찾을 수 없어 건너뜁니다. ---")
                    continue

                final_result = processor.run_analysis_pipeline(code_snippet)
                
                output_filepath = os.path.join(result_base_dir, f"{current_id}.json")
                with open(output_filepath, 'w', encoding='utf-8') as f:
                    json.dump(final_result, f, indent=4, ensure_ascii=False)
                
                print(f"--- ID: {current_id} 처리 완료 및 결과 저장 성공: {output_filepath} ---")

            except Exception as e:
                print(f"\n!!!!!! ID: {current_id} 처리 중 에러 발생. 건너뜁니다. !!!!!!")
                print(f"에러 상세: {e}", file=sys.stderr)
                continue
        
        print(f"\n{'='*20} 모든 작업이 완료되었습니다. {'='*20}")

    # 2. 단일 처리 모드 (JSON 파일에서)
    elif args.json_file and args.id:
        if args.code:
            parser.error("--json-file 옵션과 직접 코드 입력은 동시에 사용할 수 없습니다.")
        try:
            code_snippet = load_code_from_json(args.json_file, args.id)
            if code_snippet is None:
                 raise FileNotFoundError(f"ID '{args.id}'에 해당하는 데이터를 찾을 수 없습니다.")

            print(f"\n코드를 성공적으로 로드했습니다. (Source: {args.json_file}, id: {args.id})")
            print("-" * 50)
            
            final_result = processor.run_analysis_pipeline(code_snippet)

            print("\n\n" + "="*20 + " FINAL REPORT " + "="*20)
            print(json.dumps(final_result, indent=4, ensure_ascii=False))
            print("="*54)
        except Exception as e:
            print(f"\n프로그램 실행 중 에러가 발생했습니다: {e}", file=sys.stderr)
            sys.exit(1)

    # 3. 단일 처리 모드 (직접 코드 입력)
    elif args.code:
        final_result = processor.run_analysis_pipeline(args.code)
        print("\n\n" + "="*20 + " FINAL REPORT " + "="*20)
        print(json.dumps(final_result, indent=4, ensure_ascii=False))
        print("="*54)
        
    # 4. 아무 인자도 없는 경우
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()