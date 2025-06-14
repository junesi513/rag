# start.py

import json
import argparse
import sys
from process import VulnerabilityProcessor # VulRAG 대신 VulnerabilityProcessor를 임포트합니다.

def load_code_from_json(json_path: str, vul_id: str) -> str:
    """JSON 파일에서 특정 id의 코드를 로드합니다."""
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if not isinstance(data, list):
            raise ValueError("JSON 파일은 배열(list) 형태여야 합니다.")
            
        target_item = next((item for item in data if item.get('id') == vul_id), None)
            
        if target_item is None:
            raise ValueError(f"ID '{vul_id}'에 해당하는 항목을 찾을 수 없습니다.")
            
        files = target_item.get('files')
        if not files or not isinstance(files, list) or len(files) == 0:
            raise ValueError("JSON 항목에 'files' 배열이 없거나 비어있습니다.")
            
        code_before = files[0].get('code_before')
        if code_before is None:
            raise ValueError("첫 번째 file 객체에 'code_before' 키가 없습니다.")
            
        return code_before
    except FileNotFoundError:
        raise FileNotFoundError(f"파일을 찾을 수 없습니다: {json_path}")
    except json.JSONDecodeError:
        raise ValueError(f"잘못된 JSON 형식입니다: {json_path}")
    except Exception as e:
        raise type(e)(f"코드를 로드하는 중 에러 발생: {e}")


def main():
    """메인 실행 함수"""
    parser = argparse.ArgumentParser(
        description='코드 취약점 분석 도구 (Code Vulnerability Analysis Tool)',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''
사용 예시:
  1. 직접 코드 입력:
     python start.py 'public class MyClass {{ ... }}'

  2. RAG 비활성화:
     python start.py --disable-rag 'public class MyClass {{ ... }}'

  3. JSON 파일에서 코드 로드:
     python start.py --json-file path/to/your/data.json --id cve-2022-1234
'''
    )
    
    parser.add_argument(
        'code',
        nargs='?',
        help='분석할 코드 (작은따옴표로 감싸서 입력)'
    )
    parser.add_argument(
        '--disable-rag',
        action='store_true',
        help='RAG 기능을 비활성화하고 LLM만 사용하여 분석'
    )
    parser.add_argument(
        '--json-file',
        help='분석할 코드가 포함된 JSON 파일 경로'
    )
    parser.add_argument(
        '--id',
        help='JSON 파일에서 로드할 코드의 ID'
    )

    args = parser.parse_args()

    code_snippet = ""
    try:
        if args.json_file:
            if not args.id:
                parser.error("--json-file 옵션을 사용할 때는 --id도 지정해야 합니다.")
            if args.code:
                parser.error("--json-file 옵션과 직접 코드 입력은 동시에 사용할 수 없습니다.")
            
            code_snippet = load_code_from_json(args.json_file, args.id)
            print(f"\n코드를 성공적으로 로드했습니다. (Source: {args.json_file}, ID: {args.id})")
            print("-" * 50)
            print(code_snippet)
            print("-" * 50)

        elif args.code:
            code_snippet = args.code
        else:
            parser.print_help()
            sys.exit(1)

        # 수정된 부분: VulnerabilityProcessor를 사용하여 파이프라인을 실행합니다.
        processor = VulnerabilityProcessor(enable_rag=not args.disable_rag)
        final_result = processor.run_analysis_pipeline(code_snippet)

        # 최종 결과를 보기 좋게 출력합니다.
        print("\n\n" + "="*20 + " FINAL REPORT " + "="*20)
        print(json.dumps(final_result, indent=4, ensure_ascii=False))
        print("="*54)

    except Exception as e:
        print(f"\n프로그램 실행 중 에러가 발생했습니다: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
