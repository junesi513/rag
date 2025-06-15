# -*- coding: utf-8 -*-

# 필요한 라이브러리를 불러옵니다.
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

def summarize_java_code(code_snippet):
    """
    CodeT5 모델을 사용하여 주어진 Java 코드 스니펫을 요약합니다.
    
    Args:
        code_snippet (str): 요약할 Java 코드 문자열
        
    Returns:
        str: 모델이 생성한 요약 텍스트
    """
    try:
        # 사용할 CodeT5 모델의 체크포인트 이름
        checkpoint = "Salesforce/codet5-base"

        # 1. 모델과 토크나이저를 Hugging Face 허브에서 불러옵니다.
        print("모델과 토크나이저를 로딩 중입니다...")
        tokenizer = AutoTokenizer.from_pretrained(checkpoint)
        model = AutoModelForSeq2SeqLM.from_pretrained(checkpoint)
        print("로딩이 완료되었습니다.")

        # 2. 입력 데이터 준비 (작업에 맞는 prefix 추가)
        # CodeT5는 특정 작업을 수행하기 위해 입력 앞에 접두사를 붙여줘야 합니다.
        task_prefix = "Summarize Java: "
        input_text = task_prefix + code_snippet

        # 3. 입력 텍스트를 토큰화합니다.
        print("코드를 토큰화하는 중입니다...")
        input_ids = tokenizer(input_text, return_tensors="pt").input_ids

        # 4. 모델을 통해 요약 결과를 생성합니다.
        print("코드 요약을 생성 중입니다...")
        # max_length: 생성될 요약의 최대 길이를 지정합니다.
        generated_ids = model.generate(input_ids, max_length=128)

        # 5. 생성된 토큰 ID를 다시 텍스트로 디코딩합니다.
        summary = tokenizer.decode(generated_ids[0], skip_special_tokens=True)
        
        return summary

    except Exception as e:
        return f"오류가 발생했습니다: {e}"

# 메인 실행 블록
if __name__ == "__main__":
    # 요약할 Java 코드 예시
    java_code = """
    public static int findMax(int[] numbers) {
        if (numbers == null || numbers.length == 0) {
            throw new IllegalArgumentException("Input array is empty or null");
        }
        int max = numbers[0];
        for (int i = 1; i < numbers.length; i++) {
            if (numbers[i] > max) {
                max = numbers[i];
            }
        }
        return max;
    }
    """
    
    # 함수를 호출하여 코드 요약 실행
    generated_summary = summarize_java_code(java_code)
    
    # 최종 결과 출력
    print("\n" + "="*50)
    print("입력된 Java 코드:")
    print(java_code)
    print("\nCodeT5가 생성한 요약:")
    print(generated_summary)
    print("="*50)