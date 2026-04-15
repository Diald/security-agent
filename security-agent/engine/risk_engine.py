from core.models import UnifiedFinding

class RiskEngine:

    @staticmethod
    def evaluate(findings: list[UnifiedFinding]) -> dict:
        """
        Returns:
        {
            "status": "PASS" | "FAIL",
            "score": int,
            "reasons": list[str]
        }
        """

        score = 0
        reasons = []

        for f in findings:
            if f.category == "secret":
                score += 100
                reasons.append("Hardcoded secret detected")
            
            elif f.category == "dependency":
                if f.severity in ("critical", "high"):
                    score += 50
                    reasons.append(
                        f"Vulnerable dependency: {f.package_name} ({f.identifier})"
                    )

            elif f.category == "sast":
                if f.severity == "high":
                    score += 10

        status = "FAIL" if score >= 50 else "PASS"

        return {
            "status": status,
            "score": score,
            "reasons": list(set(reasons)),
        }