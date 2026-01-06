from pydantic import BaseModel
from typing import Optional, List

class SASTFinding(BaseModel):
    tool: str
    rule_id: str
    severity: str
    message: str
    file_path: str
    line_start: int
    line_end: int
    confidence: Optional[str] = None
    
class DependencyFinding(BaseModel):
    tool: str # "osv-scanner"
    ecosystem: str #"PyPI"
    package_name: str # "requests"
    installed_version: Optional[str]
    fixed_version: Optional[str]
    
    vulnerability_id: str #"CVE-2023-32681..."
    severity: Optional[str]
    summary: str
    
    affected_range: Optional[str]
    references: Optional[List[str]]
    
    confidence: str="high"
    
class SecretFinding(BaseModel):
    tool: str
    secret_type: str
    detector: Optional[str]
    
    file_path: str
    line_start: Optional[int]
    line_end: Optional[int]
    
    fingerprint: str
    verified: bool
    
    severity: str
    confidence:str
    
    message: Optional[str] = None
    
class UnifiedFinding(BaseModel):
    source: str # bandit / osv-scanner / trufflehog
    category: str # sast / dependency / secret 
    
    severity: str   # critical / high / medium / low 
    confidence: str # high/ medium / low 
    
    identifier: Optional[str]
    message: str 
    
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    
    package_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    
    references: Optional[List[str]] = None