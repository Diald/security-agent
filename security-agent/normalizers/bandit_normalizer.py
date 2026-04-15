from core.models import UnifiedFinding, SASTFinding

class BanditNormalizer: 
    
    @staticmethod
    def normalize(findings: list[SASTFinding]) -> list[UnifiedFinding]:
        normalized = []
        
        for f in findings: 
            # suppression rules
            if "/tests/" in f.file_path.replace("\\", "/"):
                continue
            
            if f.severity.lower() == "low":
                continue
            
            unified = UnifiedFinding(
                source="bandit", 
                category="sast", 
                severity= f.severity.lower(),
                confidence=f.confidence.lower(),
                identifier= f.rule_id, 
                message= f.message, 
                file_path = f.file_path, 
                line_start = f.line_start,
                line_end = f.line_end, 
            )
            
            normalized.append(unified)
            
        return normalized