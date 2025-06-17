# prompt.py (정리된 최종 버전)
import json

### 1. 기능 의미 추출 ###
EXTRACT_SEMANTICS_PROMPT = """You are a system that converts code into a structured JSON format.
Your task is to summarize the code's purpose and its overall behavior in a single, concise sentence for each field.
Your only job is to provide a valid JSON object. Do not add any text or explanations before or after the JSON object.
{{
    "purpose": "To provide a utility function for adding two integers.",
    "behavior": "It takes two integers as input and returns their sum."
}}

{code}
"""

### 1. RAG 모드용 분석 및 JSON 생성 프롬프트 ###
RAG_ANALYZE_JSON_PROMPT = """You are a world-class cybersecurity expert. Your SOLE task is to analyze the user's code, using the provided reference vulnerability, and generate a JSON object summarizing your findings.
DO NOT write any introduction or explanation outside the JSON structure. Your entire response MUST be a single, valid JSON object.
[Reference Vulnerability Information]
{reference_info}
[Code to Analyze]
{code}
IMPORTANT: Based on the reference and the code, respond with ONLY a JSON object in this exact format.
{{
    "analysis_summary": "A concise summary explaining how the code is vulnerable in relation to the reference CVE.",
    "severity": "High/Medium/Low",
    "vulnerable_sections": [
        {{
            "vulnerable_lines": "start-end",
            "code_snippet": "The exact, original vulnerable code snippet.",
            "reason": "A detailed explanation of why this specific section is vulnerable."
        }}
    ]
}}
"""

### 2. Direct 모드용 분석 및 JSON 생성 프롬프트 ###
DIRECT_ANALYZE_JSON_PROMPT = """You are a world-class cybersecurity expert. Your SOLE task is to meticulously analyze the user's code ON ITS OWN to find potential security flaws and generate a JSON object summarizing your findings.
DO NOT write any introduction or explanation outside the JSON structure. Your entire response MUST be a single, valid JSON object.
[Code to Analyze]
{code}
IMPORTANT: Critically analyze the code and respond with ONLY a JSON object in this exact format. If no vulnerabilities are found, return an empty list for "vulnerable_sections".
{{
    "analysis_summary": "A concise summary of your findings. If the code is secure, state that.",
    "severity": "High/Medium/Low/Not Vulnerable",
    "vulnerable_sections": [
        {{
            "vulnerable_lines": "start-end",
            "code_snippet": "The exact, original vulnerable code snippet.",
            "reason": "A detailed explanation of why this specific section is vulnerable."
        }}
    ]
}}
"""
### 3a. RAG 모드용 수리 계획 생성 프롬프트 ###
RAG_GENERATE_REPAIR_PLAN_PROMPT = """You are a program repair specialist. Based on the provided vulnerability analysis from a known CVE, generate a detailed, step-by-step plan to fix the code.
The plan must consist of atomic operations (Insert, Update, Delete). You must generate 10 operations.

[Vulnerability Analysis]
{analysis_json}

[Original Buggy Code]
{original_code}

IMPORTANT: Respond with ONLY a JSON object in the following format. For each operation, provide a code complexity score from 1 (simple) to 10 (complex), You must generate exactly 10 candidates.

{{
    "repair_operations": [
        {{
            "type": "Update",
            "line_number": "The line number in the original code *before* which to modify the code.",
            "code_to_update": "The code being updated.",
            "complexity": 5
        }},
        {{
            "type": "Insert",
            "line_number": "The line number in the original code *before* which to insert the new code.",
            "code_to_add": "The new code being added.",
            "complexity": 3
        }},
        {{
            "type": "Delete",
            "line_number": "The line number in the original code *before* which to delete the code.",
            "code_to_delete": "The code being deleted.",
            "complexity": 2
        }}
        ...
        ...
    ]
}}
"""

### 3b. Direct 모드용 단일 패치 생성 프롬프트 ###
DIRECT_GENERATE_PATCH_PROMPT="""You are a program repair specialist. Based on the provided vulnerability analysis from a known CVE, generate a detailed, step-by-step plan to fix the code.
The plan must consist of atomic operations (Insert, Update, Delete). You must generate 10 operations.

[Vulnerability Analysis]
{analysis_json}

[Original Buggy Code]
{original_code}

IMPORTANT: Respond with ONLY a JSON object in the following format. For each operation, provide a code complexity score from 1 (simple) to 10 (complex), You must generate exactly 10 candidates.

{{
    "repair_operations": [
        {{
            "type": "Update",
            "line_number": "The line number in the original code *before* which to modify the code.",
            "code_to_update": "The code being updated.",
            "complexity": 5
        }},
        {{
            "type": "Insert",
            "line_number": "The line number in the original code *before* which to insert the new code.",
            "code_to_add": "The new code being added.",
            "complexity": 3
        }},
        {{
            "type": "Delete",
            "line_number": "The line number in the original code *before* which to delete the code.",
            "code_to_delete": "The code being deleted.",
            "complexity": 2
        }}
        ...
        ...
    ]
}}
"""


### Helper 함수 (재추가) ###
def get_semantics_info(semantics_data=None):
    if not semantics_data or semantics_data.get("purpose") == "Unknown":
        return ""
    # JSON 문자열이 아닌, 사람이 읽기 좋은 형태로 포맷팅
    purpose = semantics_data.get('purpose', 'N/A')
    behavior = semantics_data.get('behavior', 'N/A')
    if isinstance(behavior, list):
        behavior = "\n".join(f"- {item}" for item in behavior)

    return f"""
[Previously Analyzed Functional Semantics]
Purpose: {purpose}
Behavior:
{behavior}
"""