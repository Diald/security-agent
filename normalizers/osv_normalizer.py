from core.models import UnifiedFinding, DependencyFinding

class OSVNormalizer:

    @staticmethod
    def normalize(findings: list[DependencyFinding]) -> list[UnifiedFinding]:
        normalized = []

        for f in findings:
            if not f.severity:
                continue

            severity = f.severity.lower()

            # SUPPRESSION RULE: only keep high & critical
            if severity not in ("high", "critical"):
                continue

            normalized.append(
                UnifiedFinding(
                    source="osv-scanner",
                    category="dependency",
                    severity=severity,
                    confidence=f.confidence,
                    identifier=f.vulnerability_id,
                    message=f.summary or "Vulnerable dependency detected",
                    package_name=f.package_name,
                    installed_version=f.installed_version,
                    fixed_version=f.fixed_version,
                    references=f.references,
                )
            )

        return normalized