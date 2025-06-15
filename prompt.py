# junesi513/rag/rag-8ee72d8e489f6f6dbff76adc48d163ed2208e189/prompt.py

import json

### 1. 기능 의미 추출
# 설명: 코드가 어떤 목적으로 어떻게 동작하는지 기능적 의미를 파악합니다. (사용자 요청 1번)
EXTRACT_SEMANTICS_PROMPT = """You are a code analysis system. Your task is to analyze the given code and extract its functional semantics.

IMPORTANT: Respond with ONLY a JSON object in this format:
{{
    "purpose": "A concise description of the code's main purpose.",
    "behavior": "A step-by-step list of the code's functional behaviors."
}}

[Code to analyze]
{code}"""

### 2. 취약점 분석
# 설명: 코드에서 취약한 부분을 최대 5개까지 찾아내고, 각 부분의 위험도, 위치, 이유를 상세히 기술합니다. (사용자 요청 2번)
ANALYZE_VULNERABILITY_PROMPT = """You are a vulnerability detection specialist. Your task is to analyze the given code to identify and detail its security vulnerabilities.
Identify up to 5 of the most critical vulnerabilities.

IMPORTANT: Respond with ONLY a JSON object in this format. If no vulnerabilities are found, return an empty list.
{{
    "vulnerabilities_found": [
        {{
            "severity": "High/Medium/Low",
            "line_range": "start_line-end_line",
            "code_snippet": "The exact, original vulnerable code snippet.",
            "explanation": "A detailed explanation of why this specific section is vulnerable."
        }}
    ]
}}

[Code to analyze]
{code}"""


### 3. 취약점 수정 계획 생성
# 설명: 분석된 취약점을 바탕으로, 'Insert', 'Update', 'Delete' 타입의 구체적인 수정 계획을 생성합니다. (사용자 요청 3번)
GENERATE_REPAIR_PLAN_PROMPT = """You are a program repair specialist. Based on the provided vulnerability analysis, generate a detailed, step-by-step plan to fix the code.
The plan should consist of atomic operations (Insert, Update, Delete). You should generate max 10 operations.

[Vulnerability Analysis]
{vulnerability_analysis_json}

[Original Buggy Code]
{original_code}


IMPORTANT: Respond with ONLY a JSON object in the following format. For each operation, provide a complexity score from 1 (simple) to 10 (complex).
{{
    "repair_operations": [
        {{
            "type": "Update",
            "line_number": "The line number of the code to be modified.",
            "code_to_update": "The code being updated.",
            "complexity": 5,
        }},
        {{
            "type": "Insert",
            "line_number": "The line number in the original code *before* which to insert the new code.",
            "code_to_add": "The new code being added.",
            "complexity": 3,
        }},
        {{
            "type": "Delete",
            "line_number": "The line number of the code to be deleted.",
            "code_to_delete": "The code being deleted.",
            "complexity": 2,
        }}
    ]
}}
"""

def get_reference_info(rag_data=None):
    if not rag_data: return ""
    return f"""
[Reference Vulnerability Information]
CVE ID: {rag_data.get('cve_id', 'Unknown')}
Vulnerability causes:
{rag_data.get('vulnerability_causes', {}).get('abstract_description', 'No abstract description available')}
"""

def get_semantics_info(semantics_data=None):
    if not semantics_data or semantics_data.get("purpose") == "Unknown":
        return ""
    return f"""
[Previously Analyzed Functional Semantics]
Purpose: {semantics_data.get('purpose', 'N/A')}
Behavior: {semantics_data.get('behavior', 'N/A')}
"""

def get_analysis_context(analysis_data=None):
    if not analysis_data or not analysis_data.get("vulnerable_sections"):
        return ""
    summary = {
        "identified_vulnerable_sections": len(analysis_data.get("vulnerable_sections", [])),
        "analysis_summary": analysis_data.get("analysis_summary", "No summary.")
    }
    return f"""
[Your Initial Detailed Analysis Summary]
{json.dumps(summary, indent=2)}
"""


### RAG
### 2. 취약점 분석 (RAG 정보를 활용하는 버전으로 복원)
ANALYZE_VULNERABILITY_PROMPT = """You are a vulnerability detection system. Your task is to analyze the given code to identify why it is vulnerable, which parts are vulnerable, and provide a summary.
Use the provided functional semantics and reference vulnerability information to enrich your analysis.

IMPORTANT: Respond with ONLY a JSON object in this format:
{{
    "analysis_summary": "A brief summary of your findings and the overall vulnerability.",
    "vulnerable_sections": [
        {{
            "vulnerable_lines": "start-end",
            "code_snippet": "The exact, original vulnerable code snippet.",
            "reason": "A detailed explanation of why this specific section is vulnerable, considering the reference info."
        }}
    ]
}}

{semantics_info}

[Code to analyze]
{code}

{reference_info}"""

### 3. 취약점 최종 판정 (복원)
JUDGE_VULNERABILITY_PROMPT = """You are a vulnerability detection system. Based on your initial analysis and the known vulnerability information provided, make a final judgment.

IMPORTANT: Respond with ONLY a JSON object in this format:
{{
    "is_vulnerable": true/false,
    "explanation": "Detailed explanation of why the code is vulnerable or not, referencing both your initial analysis and the known vulnerability.",
    "severity": "high/medium/low",
    "recommendation": "Specific recommendations to fix the vulnerability if it exists."
}}

{initial_analysis}

[Code to analyze]
{code}

[Known vulnerability information]
CVE ID: {cve_id}
Vulnerability causes:
{vulnerability_causes}

[Patch Information]
{patch_info}"""

### 3-1. 취약점 최종 판정 (Direct 모드용) (신규 추가)
# 설명: RAG 정보 없이, 상세 분석 결과만으로 최종 판정을 내립니다.
DIRECT_JUDGE_VULNERABILITY_PROMPT = """You are a vulnerability detection system. Based on the detailed analysis you just performed on the code, make a final, self-contained judgment.

IMPORTANT: Respond with ONLY a JSON object in the following format. You must determine the severity based on your analysis.
{{
    "is_vulnerable": true/false,
    "explanation": "Detailed explanation of why the code is vulnerable or not, based on your analysis findings.",
    "severity": "high/medium/low",
    "recommendation": "Specific recommendations to fix the vulnerability if it exists."
}}

[Your Initial Detailed Analysis Summary]
{initial_analysis}

[Code to analyze]
{code}
"""