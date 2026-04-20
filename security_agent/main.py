import json
import argparse
import os
import logging
logger = logging.getLogger(__name__)

from concurrent.futures import ThreadPoolExecutor, as_completed

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
    
def _run_bandit(repo_path):
    logger.info("[*] Running SAST scan (Bandit)...")
    runner = BanditRunner()
    parser = BanditParser()
    raw = runner.run(repo_path)
    findings = parser.parse(raw)
    unified = BanditNormalizer.normalize(findings)
    logger.info(f"[+] Found {len(unified)} SAST issues")
    return unified

def _run_osv(repo_path):
    logger.info("[*] Running dependency scan (OSV)...")
    runner = OSVRunner()
    parser = OSVParser()
    raw = runner.run(repo_path)
    findings = parser.parse(raw)
    unified = OSVNormalizer.normalize(findings)
    logger.info(f"[+] Found {len(unified)} dependency issues")
    return unified

def _run_trufflehog(repo_path):
    logger.info("[*] Running secret scan (TruffleHog)...")
    runner = TruffleHogRunner()
    parser = TruffleHogParser()
    raw = runner.run(repo_path)
    findings = parser.parse(raw)
    unified = TruffleHogNormalizer.normalize(findings)
    logger.info(f"[+] Found {len(unified)} secret issues")
    return unified

def run_scan(repo_path: str, output_dir: str = "reports/", report_format: str = "json", db_url: str = None):
    """Main scanning function - returns report dict"""
    
    logger.info(f"\n[*] Starting security scan on: {repo_path}")
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        # ============================================================
        # Run all scanners in parallel
        # ============================================================
        scanners = {
            "bandit":     _run_bandit,
            "osv":        _run_osv,
            "trufflehog": _run_trufflehog,
            }

        all_results = {"bandit": [], "osv": [], "trufflehog": []}
        failed = []

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(fn, repo_path): name
                for name, fn in scanners.items()
            }

            for future in as_completed(futures):
                name = futures[future]
                try:
                    all_results[name] = future.result()
                except Exception as e:
                    logger.info(f"[!] {name} scanner failed: {e}")
                    failed.append(name)

        if failed:
            logger.info(f"[!] Scanners that failed: {', '.join(failed)}")

        bandit_unified     = all_results["bandit"]
        osv_unified        = all_results["osv"]
        secret_unified = all_results["trufflehog"]

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
        
        logger.info(f"\n[*] Total findings (after filtering): {len(all_findings)}")
            
        # ============================================================
        # Risk evaluation
        # ============================================================            
        logger.info("[*] Running risk evaluation...")
        decision = RiskEngine.evaluate(all_findings)

        logger.info(f"[+] Status: {decision['status']}")
        logger.info(f"[+] Score: {decision['score']}")

        # ============================================================
        # Report Generation
        # ============================================================            
        
        json_report_path = os.path.join(output_dir, "security_report.json")
        md_report_path = os.path.join(output_dir, "security_report.md")
        
        ReportGenerator.to_json(all_findings, decision, json_report_path)
        ReportGenerator.to_markdown(all_findings, decision, md_report_path)
        
        logger.info(f"[+] JSON report: {json_report_path}")
        logger.info(f"[+] Markdown report: {md_report_path}")
        
        # ============================================================
        # LLM Assessment (Optional)
        # ============================================================    
        
        assessment = "Manual review required"
        if HAS_LLM:
            try:
                logger.info("[*] Running LLM assessment (Gemini)...")
                with open(json_report_path, "r", encoding="utf-8") as f:
                    security_report = json.load(f)

                prompt = AssessmentPromptBuilder.build(security_report)
                client = GeminiClient()
                assessment = client.analyze(prompt)
                logger.info("[+] LLM assessment complete")
            except Exception as e:
                logger.error(f"[!] LLM assessment failed: {e}")
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
        logger.error(f"[!] An error occurred: {str(e)}")
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
        
        logger.info("\n" + "="*60)
        logger.info(f"Status: {report['summary']['status']}")
        logger.info(f"Score: {report['summary']['score']}")
        logger.info(f"Total Findings: {len(report['findings'])}")
        logger.info("="*60)
        
        exit_code = 0 if report['summary']['status'] == 'PASS' else 1
        return exit_code
        
    except Exception as e:
        logger.error(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())