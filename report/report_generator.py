import json
from core.models import UnifiedFinding

class ReportGenerator:
    
    @staticmethod
    def to_json(
        findings: list[UnifiedFinding],
        decision: dict, 
        output_path: str = "security_report.json",
    ):
        report = {
            "summary": decision, 
            "findings": [f.model_dump() for f in findings],
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
            
        return output_path
    
    @staticmethod
    def to_markdown(
        findings: list[UnifiedFinding],
        decision: dict, 
        output_path: str = "security_report.md",
    ):
        lines = []
        
        lines.append("# Security Report\n")
        lines.append(f"**Status:** {decision['score']}\n")
        lines.append(f"**Risk Score:** {decision['score']}\n")
        
        if decision["reasons"]:
            lines.append('## Reasons for decision\n')
            for r in decision["reasons"]:
                lines.append(f"- {r}")
            lines.append("")
        
        lines.append("## Findings\n")
        
        for f in findings:
            lines.append(f"### [{f.category.upper()}] {f.identifier or 'Finding'}")
            lines.append(f" - **Source:** {f.source}")
            lines.append(f"- **Severity:** {f.severity}")
            lines.append(f"- **Confidence:** {f.confidence}")
            lines.append(f"- **Message:** {f.message}")
            
            if f.file_path:
                lines.append(f"- **File:** {f.file_path}")
                if f.line_start:
                    lines.append(f"- **Lines:** {f.line_start}")
            
            if f.package_name:
                lines.append(f"- **Package:** {f.package_name}")
                lines.append(f"{f.installed_version} -> {f.fixed_version}")
                
            if f.references:
                lines.append("- **References:**")
                for ref in f.references:
                    lines.append(f"  - {ref}")

            lines.append("")
            
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
            
        return output_path
                    