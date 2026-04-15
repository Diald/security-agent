# --------------------
# SAST
# --------------------
from scanners.sast.bandit_runner import BanditRunner
from scanners.sast.bandit_parser import BanditParser

# --------------------
# Dependency scanning
# --------------------
from scanners.dependency.OSVRunner import OSVRunner
from scanners.dependency.OSVParser import OSVParser

# --------------------
# Secret scanning
# --------------------
from scanners.secret_scanning.TruffleHog_runner import TruffleHogRunner
from scanners.secret_scanning.TruffleHog_parser import TruffleHogParser


# --------------------
# Normalizers
# --------------------

from normalizers.bandit_normalizer import BanditNormalizer
from normalizers.osv_normalizer import OSVNormalizer
from normalizers.trufflehog_normalizer import TruffleHogNormalizer


# ----------------------
# Risk Engine 
# ----------------------

from engine.risk_engine import RiskEngine

# ----------------------
# Report generator 
# ----------------------

from report.report_generator import ReportGenerator

# ----------------------
# LLM - Gemini
# ----------------------
from llm.llm import GeminiClient
from llm.assessment_prompt import AssessmentPromptBuilder

import json
import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-path", required=True, help="Path to the repo that needs to be scanned")
    args = parser.parse_args()
    
    repo_path = args.repo_path

    try:
        # ============================================================
        # SAST — Bandit
        # ============================================================
        bandit_runner = BanditRunner()
        bandit_parser = BanditParser()

        bandit_raw = bandit_runner.run(repo_path)
        sast_findings = bandit_parser.parse(bandit_raw)
        bandit_unified = BanditNormalizer.normalize(sast_findings)

        print("\n=== SAST Findings (Bandit) ===")
        
        for f in bandit_unified:
            print(f)

        # ============================================================
        # Supply Chain — OSV
        # ============================================================
        osv_runner = OSVRunner()
        osv_parser = OSVParser()

        osv_raw = osv_runner.run(repo_path)
        dep_findings = osv_parser.parse(osv_raw)
        osv_unified = OSVNormalizer.normalize(dep_findings)

        # print("\n=== Dependency Findings (OSV) ===")
        # for f in osv_unified:
        #     print(f)

        # ============================================================
        # Secrets — TruffleHog
        # ============================================================
        trufflehog_runner = TruffleHogRunner()
        trufflehog_parser = TruffleHogParser()

        secret_raw = trufflehog_runner.run(repo_path)
        print(secret_raw)
        secret_findings = trufflehog_parser.parse(secret_raw)
        secret_unified = TruffleHogNormalizer.normalize(secret_findings)

        print("\n=== Secret Findings (TruffleHog) ===")
        for f in secret_unified:
            print(f)
            
        # ============================================================
        # ALL FINDINGS UNIFORMED 
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
        
        print("\n=== Unified Findings ===")
        for f in all_findings:
            print(f)
            
            
        # ============================================================
        # Risk evaluation
        # ============================================================            
        decision = RiskEngine.evaluate(all_findings)

        print("\n=== Final Decision ===")
        print(f"Status : {decision['status']}")
        print(f"Score  : {decision['score']}")

        if decision["reasons"]:
            print("\nReasons:")
            for r in decision["reasons"]:
                print(f"- {r}")
        # ============================================================
        # Report Generation
        # ============================================================            
        
        json_report = ReportGenerator.to_json(all_findings, decision)
        md_report = ReportGenerator.to_markdown(all_findings, decision)
        
        print("\nReport Generated:")
        print(f"- {json_report}")
        print(f"- {md_report}")
        
        # ============================================================
        # LLM Report
        # ============================================================    
        
        with open(json_report, "r", encoding="utf-8") as f:
            security_report = json.load(f)

        prompt = AssessmentPromptBuilder.build(security_report)
        print("==== PROMPT START ====")
        print(prompt)
        print("==== PROMPT END ====")

        client = GeminiClient()
        assessment = client.analyze(prompt)

        print("\n=== LLM Security Assessment ===\n")
        print(assessment)
        
    except Exception as e:
        print(f"[!] An error occurred: {str(e)}")

if __name__ == "__main__":
    main()