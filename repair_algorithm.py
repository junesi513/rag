from typing import Dict, List, Any, Optional
import re
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

class RepairAlgorithm:
    def __init__(self, model_name: str = "microsoft/codebert-base"):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForCausalLM.from_pretrained(model_name).to(self.device)
        
    def generate_repair_suggestions(self, 
                                  vulnerable_code: str, 
                                  vulnerability_type: str,
                                  reference_fixes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """취약점 수정 제안을 생성합니다."""
        suggestions = []
        
        # 참조 수정사항 기반 제안 생성
        for ref_fix in reference_fixes:
            if ref_fix["vulnerability_type"] == vulnerability_type:
                suggestion = self._apply_reference_fix(vulnerable_code, ref_fix)
                if suggestion:
                    suggestions.append(suggestion)
        
        # 모델 기반 제안 생성
        model_suggestion = self._generate_model_based_fix(vulnerable_code, vulnerability_type)
        if model_suggestion:
            suggestions.append(model_suggestion)
            
        return suggestions
    
    def _apply_reference_fix(self, 
                           vulnerable_code: str, 
                           reference_fix: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """참조 수정사항을 현재 코드에 적용합니다."""
        try:
            # 패턴 매칭을 통한 수정
            pattern = reference_fix.get("pattern")
            replacement = reference_fix.get("replacement")
            
            if pattern and replacement:
                fixed_code = re.sub(pattern, replacement, vulnerable_code)
                if fixed_code != vulnerable_code:
                    return {
                        "fixed_code": fixed_code,
                        "explanation": reference_fix.get("explanation", "Reference-based fix applied"),
                        "confidence": reference_fix.get("confidence", 0.8)
                    }
        except Exception as e:
            print(f"Error applying reference fix: {str(e)}")
            
        return None
    
    def _generate_model_based_fix(self, 
                                vulnerable_code: str, 
                                vulnerability_type: str) -> Optional[Dict[str, Any]]:
        """모델을 사용하여 수정 제안을 생성합니다."""
        try:
            prompt = f"""
            Fix the following vulnerable code that has a {vulnerability_type} vulnerability:
            
            {vulnerable_code}
            
            Fixed code:
            """
            
            inputs = self.tokenizer(prompt, return_tensors="pt", padding=True, truncation=True)
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_length=512,
                    num_return_sequences=1,
                    temperature=0.7,
                    top_p=0.95
                )
                
            fixed_code = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            fixed_code = fixed_code.replace(prompt, "").strip()
            
            if fixed_code != vulnerable_code:
                return {
                    "fixed_code": fixed_code,
                    "explanation": "Model-generated fix",
                    "confidence": 0.6
                }
                
        except Exception as e:
            print(f"Error generating model-based fix: {str(e)}")
            
        return None
    
    def validate_fix(self, 
                    original_code: str, 
                    fixed_code: str, 
                    vulnerability_type: str) -> Dict[str, Any]:
        """수정된 코드의 유효성을 검증합니다."""
        validation_result = {
            "is_valid": False,
            "confidence": 0.0,
            "explanation": ""
        }
        
        try:
            # 기본 검증
            if fixed_code == original_code:
                validation_result["explanation"] = "No changes were made to the code"
                return validation_result
                
            # 구문 검증
            if not self._validate_syntax(fixed_code):
                validation_result["explanation"] = "Fixed code has syntax errors"
                return validation_result
                
            # 취약점 제거 검증
            if self._check_vulnerability_removed(fixed_code, vulnerability_type):
                validation_result.update({
                    "is_valid": True,
                    "confidence": 0.8,
                    "explanation": "Vulnerability appears to be fixed"
                })
                
        except Exception as e:
            validation_result["explanation"] = f"Validation error: {str(e)}"
            
        return validation_result
    
    def _validate_syntax(self, code: str) -> bool:
        """코드의 구문을 검증합니다."""
        try:
            # 여기에 구문 검증 로직 구현
            # 예: ast.parse() 사용
            return True
        except:
            return False
    
    def _check_vulnerability_removed(self, code: str, vulnerability_type: str) -> bool:
        """취약점이 제거되었는지 확인합니다."""
        try:
            # 취약점 패턴 검사
            patterns = {
                "injection": r"(?i)(eval|exec|system|os\.system)",
                "xss": r"(?i)(<script|javascript:|on\w+\s*=)",
                "sql_injection": r"(?i)(SELECT|INSERT|UPDATE|DELETE).*WHERE.*=.*'",
                # 추가 패턴들...
            }
            
            if vulnerability_type in patterns:
                return not bool(re.search(patterns[vulnerability_type], code))
                
            return True
            
        except Exception as e:
            print(f"Error checking vulnerability removal: {str(e)}")
            return False 