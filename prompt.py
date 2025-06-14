# junesi513/rag/rag-8ee72d8e489f6f6dbff76adc48d163ed2208e189/prompt.py

"""프롬프트 템플릿 관리"""
import json

EXTRACT_SEMANTICS_PROMPT = """You are a code analysis system. Your task is to analyze the given vulnerable code and extract its functional semantics.

IMPORTANT: Respond with ONLY a JSON object in this format:
{{
    "purpose": "Function purpose: [main purpose]",
    "behavior": "The functions of the code snippet are:\\n1. [first behavior]\\n2. [second behavior]\\n..."
}}

[Code to analyze]
{code}"""

ANALYZE_VULNERABILITY_PROMPT = """You are a vulnerability detection system. Your task is to analyze the given code to identify why it is vulnerable, which parts are vulnerable, and provide a summary.

IMPORTANT: Respond with ONLY a JSON object in this format:
{{
    "analysis_summary": "A brief summary of your findings and the overall vulnerability.",
    "vulnerable_sections": [
        {{
            "vulnerable_lines": "start-end",
            "code_snippet": "The exact, original vulnerable code snippet.",
            "reason": "A detailed explanation of why this specific section is vulnerable."
        }}
    ]
}}

{semantics_info}

[Code to analyze]
{code}

{reference_info}"""

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

REPAIR_PROMPT = """You are a security expert specializing in fixing code vulnerabilities. Based on the following vulnerability analysis, your task is to provide specific line-by-line repair suggestions.

[Vulnerability Analysis]
{vulnerability_analysis_json}

IMPORTANT: For each vulnerable section identified in the analysis, provide a repair suggestion in the following JSON format. Respond with ONLY the JSON object. Do not provide the full repaired code.
{{
  "repair_suggestions": [
    {{
      "line_number": "The line number of the code that needs modification.",
      "original_content": "The original, vulnerable line of code.",
      "suggested_modification": "The suggested, repaired line of code.",
      "reason_for_change": "A brief explanation of why this change is necessary."
    }}
  ]
}}
"""

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
