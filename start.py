from rag import VulRAG
import os
import sys
import argparse

def main():
    # 커맨드라인 인자 파싱
    parser = argparse.ArgumentParser(
        description='코드 취약점 분석 도구 (Code Vulnerability Analysis Tool)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
사용 예시:
  # RAG를 사용하여 취약점 분석 (기본 모드)
  python start.py 'def process_input(user_input):\\n    cmd = f"ls {user_input}"\\n    os.system(cmd)'

  # RAG 비활성화 모드로 취약점 분석 (LLM만 사용)
  python start.py --disable-rag 'def vulnerable_code():\\n    pass'

참고:
  - RAG 모드(기본)는 Elasticsearch의 취약점 데이터베이스를 활용하여 더 정확한 분석을 제공합니다.
  - RAG 비활성화 모드는 LLM만을 사용하여 빠른 분석을 제공하지만, 정확도가 다소 낮을 수 있습니다.
  - 분석하려는 코드에 줄바꿈이 있는 경우 \\n을 사용하여 표현하세요.
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
        help='RAG 기능을 비활성화하고 LLM만 사용하여 분석 (기본값: RAG 활성화)'
    )

    args = parser.parse_args()

    if not args.code:
        parser.print_help()
        sys.exit(1)

    # create VulRAG instance
    rag = VulRAG(enable_rag=not args.disable_rag)

    # execute vulnerability detection
    result = rag.detect_vulnerabilities(args.code)

    # print result
    print("\n=== vulnerability detection result ===")
    print(f"status: {result['status']}")
    if result['details']:
        print("\nvulnerability details:")
        for key, value in result['details'].items():
            print(f"{key}: {value}")

def test_vul_rag():
    # code with vulnerability (race condition)
    vulnerable_code = """
    void process_data() {
        // This code has a race condition vulnerability
        rcu_read_lock();
        shared_data->value++;
        rcu_read_unlock();
    }
    """
    
    # fixed code
    fixed_code = """
    void process_data() {
        // This code uses spin_lock to prevent race condition
        spin_lock(&lock);
        shared_data->value++;
        spin_unlock(&lock);
    }
    """
    
    # create Vul-RAG instance
    vul_rag = VulRAG()
    
    print("\n=== test vulnerable code ===")
    result1 = vul_rag.detect_vulnerabilities(vulnerable_code)
    print("\nresult:")
    if result1["status"] == "vulnerable":
        print("vulnerability found!")
        print(f"vulnerability ID: {result1['details']['vulnerability_id']}")
        print(f"cause: {result1['details']['cause']}")
        print(f"solution: {result1['details']['solution']}")
    else:
        print("no vulnerability found")
    
    print("\n=== test fixed code ===")
    result2 = vul_rag.detect_vulnerabilities(fixed_code)
    print("\nresult:")
    if result2["status"] == "vulnerable":
        print("vulnerability found!")
        print(f"vulnerability ID: {result2['details']['vulnerability_id']}")
        print(f"cause: {result2['details']['cause']}")
        print(f"solution: {result2['details']['solution']}")
    else:
        print("no vulnerability found")

if __name__ == "__main__":
    main() 