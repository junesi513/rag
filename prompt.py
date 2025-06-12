"""프롬프트 템플릿 관리"""

EXTRACT_SEMANTICS_PROMPT = """You are a code analysis system. Your task is to analyze the given code and extract its functional semantics.

IMPORTANT: Respond with ONLY a JSON object in this format:
{{
    "purpose": "Function purpose: [main purpose]",
    "behavior": "The functions of the code snippet are:\\n1. [first behavior]\\n2. [second behavior]\\n..."
}}

[Code to analyze]
{code}"""

ANALYZE_VULNERABILITY_PROMPT = """You are a vulnerability detection system. Your task is to analyze the given code and extract potentially vulnerable parts.

IMPORTANT: Respond with ONLY a JSON object in this format:
{{
    "vulnerable_code": [
        {{
            "code": "the exact vulnerable code snippet",
            "root_cause": "the root cause of the vulnerability",
            "line_start": start line number,
            "line_end": end line number,
            "reason": "why this code is potentially vulnerable",
            "patch_before": "the vulnerable code snippet that needs to be fixed",
            "patched": "the fixed version of the code that addresses the vulnerability",
            "added_lines": [
                {{
                    "line": "the new line of code that was added",
                    "purpose": "why this line was added"
                }}
            ],
            "deleted_lines": [
                {{
                    "line": "the line of code that was removed",
                    "reason": "why this line was removed"
                }}
            ],
            "required_changes": [
                {{
                    "type": "import/variable/function/configuration",
                    "content": "what needs to be added",
                    "reason": "why this change is needed"
                }}
            ]
        }}
    ],
    "risk_level": "high/medium/low",
    "vulnerability_type": "type of vulnerability (e.g., SQL Injection, XSS, etc.)",
    "patch_description": "A brief description of how the vulnerability was fixed"
}}

[Code to analyze]
{code}

{reference_info}"""

JUDGE_VULNERABILITY_PROMPT = """You are a vulnerability detection system. Your task is to analyze if the given code contains a similar vulnerability pattern to a known vulnerability.

IMPORTANT: Respond with ONLY a JSON object in this format:
{{
    "is_vulnerable": true/false,
    "explanation": "Detailed explanation of why the code is vulnerable or not vulnerable",
    "severity": "high/medium/low",
    "recommendation": "Specific recommendations to fix the vulnerability if it exists"
}}

[Code to analyze]
{code}

[Known vulnerability information]
CVE ID: {cve_id}
Vulnerability causes:
{vulnerability_causes}

[Patch Information]
{patch_info}"""

DIRECT_ANALYSIS_PROMPT = """You are a vulnerability detection system. Your task is to analyze the provided code snippet directly for any potential security vulnerabilities.

IMPORTANT: Respond with ONLY a JSON object in this format:
{{
    "is_vulnerable": true/false,
    "explanation": "Detailed explanation of why the code is vulnerable or not",
    "severity": "high/medium/low/none",
    "recommendation": "Specific recommendations to fix the vulnerability if it exists"
}}

[Code to analyze]
{code}"""

def get_reference_info(rag_data=None):
    """RAG 데이터가 있는 경우 참조 정보 생성"""
    if not rag_data:
        return ""
    
    return f"""
[Reference Vulnerability Information]
CVE ID: {rag_data.get('cve_id', 'Unknown')}
Vulnerability causes:
{rag_data.get('vulnerability_causes', {}).get('abstract_description', 'No abstract description available')}
{rag_data.get('vulnerability_causes', {}).get('detailed_description', 'No detailed description available')}

Fixing solution:
{rag_data.get('fixing_solutions', {}).get('solution_description', 'No solution available')}""" 