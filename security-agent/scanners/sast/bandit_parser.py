from typing import List
from core.models import SASTFinding


class BanditParser:
    def parse(self, raw: dict) -> List[SASTFinding]:
        findings = []

        for issue in raw.get("results", []):
            findings.append(
                SASTFinding(
                    tool="bandit",
                    rule_id=issue.get("test_id"),
                    severity=issue.get("issue_severity", "").lower(),
                    message=issue.get("issue_text"),
                    file_path=issue.get("filename"),
                    line_start=issue.get("line_number"),
                    line_end=issue.get("line_number"),
                    confidence=issue.get("issue_confidence", "").lower()
                )
            )

        return findings