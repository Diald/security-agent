import json
import argparse
import os

# --------------------
# SAST
# --------------------
from .scanners.sast.bandit_runner import BanditRunner
from .scanners.sast.bandit_parser import BanditParser

# --------------------
# Dependency scanning
# --------------------
from .scanners.dependency.OSVRunner import OSVRunner
from .scanners.dependency.OSVParser import OSVParser

# --------------------
# Secret scanning
# --------------------
from .scanners.secret_scanning.TruffleHog_runner import TruffleHogRunner
from .scanners.secret_scanning.TruffleHog_parser import TruffleHogParser

# --------------------
# Normalizers
# --------------------
from .normalizers.bandit_normalizer import BanditNormalizer
from .normalizers.osv_normalizer import OSVNormalizer
from .normalizers.trufflehog_normalizer import TruffleHogNormalizer

# ----------------------
# Risk Engine 
# ----------------------
from .engine.risk_engine import RiskEngine

# ----------------------
# Report generator 
# ----------------------
from .report.report_generator import ReportGenerator

# ----------------------
# LLM - Gemini
# ----------------------
try:
    from .llm.llm import GeminiClient
    from .llm.assessment_prompt import AssessmentPromptBuilder
    HAS_LLM = True
except ImportError:
    HAS_LLM = False


def run_scan(repo_path: str, output_dir: str = "reports/", report_format: str = "json", db_url: str = None):
    """Main scanning function - returns report dict"""
    
    print(f"\n[*] Starting security scan on: {repo_path}")
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        # ============================================================
        # SAST — Bandit
        # ============================================================
        print("[*] Running SAST scan (Bandit)...")
        bandit_runner = BanditRunner()
        bandit_parser = BanditParser()

        bandit_raw = bandit_runner.run(repo_path)
        sast_findings = bandit_parser.parse(bandit_raw)
        bandit_unified = BanditNormalizer.normalize(sast_findings)
        print(f"[+] Found {len(bandit_unified)} SAST issues")

        # ============================================================
        # Supply Chain — OSV
        # ============================================================
        print("[*] Running dependency scan (OSV)...")
        osv_runner = OSVRunner()
        osv_parser = OSVParser()

        osv_raw = osv_runner.run(repo_path)
        dep_findings = osv_parser.parse(osv_raw)
        osv_unified = OSVNormalizer.normalize(dep_findings)
        print(f"[+] Found {len(osv_unified)} dependency issues")

        # ============================================================
        # Secrets — TruffleHog
        # ============================================================
        print("[*] Running secret scan (TruffleHog)...")
        trufflehog_runner = TruffleHogRunner()
        trufflehog_parser = TruffleHogParser()

        secret_raw = trufflehog_runner.run(repo_path)
        secret_findings = trufflehog_parser.parse(secret_raw)
        secret_unified = TruffleHogNormalizer.normalize(secret_findings)
        print(f"[+] Found {len(secret_unified)} secret issues")
            
        # ============================================================
        # ALL FINDINGS FILTERED
        # ============================================================
        
        EXCLUDED_PATH_PATTERNS = [
            "node_modules",
            ".git",
            "vendor",
            "__pycache__",
            ".venv",
            "dist",
            "build",
        ]

        def is_excluded(file_path: str) -> bool:
            if not file_path:
                return False
            normalized = file_path.replace("\\", "/")
            return any(pattern in normalized for pattern in EXCLUDED_PATH_PATTERNS)
        
        sum_all = bandit_unified + osv_unified + secret_unified
        all_findings = [f for f in sum_all if not is_excluded(f.file_path)]
        
        print(f"\n[*] Total findings (after filtering): {len(all_findings)}")
            
        # ============================================================
        # Risk evaluation
        # ============================================================            
        print("[*] Running risk evaluation...")
        decision = RiskEngine.evaluate(all_findings)

        print(f"[+] Status: {decision['status']}")
        print(f"[+] Score: {decision['score']}")

        # ============================================================
        # Report Generation
        # ============================================================            
        
        json_report_path = os.path.join(output_dir, "security_report.json")
        md_report_path = os.path.join(output_dir, "security_report.md")
        
        ReportGenerator.to_json(all_findings, decision, json_report_path)
        ReportGenerator.to_markdown(all_findings, decision, md_report_path)
        
        print(f"[+] JSON report: {json_report_path}")
        print(f"[+] Markdown report: {md_report_path}")
        
        # ============================================================
        # LLM Assessment (Optional)
        # ============================================================    
        
        assessment = "Manual review required"
        if HAS_LLM:
            try:
                print("[*] Running LLM assessment (Gemini)...")
                with open(json_report_path, "r", encoding="utf-8") as f:
                    security_report = json.load(f)

                prompt = AssessmentPromptBuilder.build(security_report)
                client = GeminiClient()
                assessment = client.analyze(prompt)
                print("[+] LLM assessment complete")
            except Exception as e:
                print(f"[!] LLM assessment failed: {e}")
                assessment = "Manual review required"
        
        # ============================================================
        # Return report
        # ============================================================
        
        report = {
            'summary': decision,
            'findings': [f.__dict__ if hasattr(f, '__dict__') else f for f in all_findings],
            'assessment': assessment
        }
        
        return report
        
    except Exception as e:
        print(f"[!] An error occurred: {str(e)}")
        import traceback
        traceback.print_exc()
        raise


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Security Agent - Multi-scanner security tool"
    )
    parser.add_argument("--repo-path", required=True, help="Path to the repository to scan")
    parser.add_argument("--output", default="reports/", help="Output directory for reports")
    parser.add_argument("--format", choices=["json", "markdown", "both"], default="json", help="Report format")
    parser.add_argument("--db-url", default=None, help="Database URL (optional)")
    
    args = parser.parse_args()
    
    try:
        report = run_scan(
            repo_path=args.repo_path,
            output_dir=args.output,
            report_format=args.format,
            db_url=args.db_url
        )
        
        print("\n" + "="*60)
        print(f"Status: {report['summary']['status']}")
        print(f"Score: {report['summary']['score']}")
        print(f"Total Findings: {len(report['findings'])}")
        print("="*60)
        
        exit_code = 0 if report['summary']['status'] == 'PASS' else 1
        return exit_code
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())