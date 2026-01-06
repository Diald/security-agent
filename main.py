from core.repo_manager import RepoManager

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


REPO_URL = "https://github.com/dehvCurtis/vulnerable-code-examples.git"


def main():
    repo_path = RepoManager.clone_repo(REPO_URL)

    try:
        # ============================================================
        # SAST — Bandit
        # ============================================================
        bandit_runner = BanditRunner()
        bandit_parser = BanditParser()

        bandit_raw = bandit_runner.run(repo_path)
        sast_findings = bandit_parser.parse(bandit_raw)
        bandit_unified = BanditNormalizer.normalize(sast_findings)

        # print("\n=== SAST Findings (Bandit) ===")
        
        # for f in bandit_unified:
        #     print(f)

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
        secret_findings = trufflehog_parser.parse(secret_raw)
        secret_unified = TruffleHogNormalizer.normalize(secret_findings)

        # print("\n=== Secret Findings (TruffleHog) ===")
        # for f in secret_unified:
        #     print(f)
            
        # ============================================================
        # ALL FINDINGS UNIFORMED 
        # ============================================================
        
        all_findings = bandit_unified + osv_unified + secret_unified
        
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

    finally:
        RepoManager.cleanup(repo_path)


if __name__ == "__main__":
    main()