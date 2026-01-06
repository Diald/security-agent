from core.models import UnifiedFinding, SecretFinding

class TruffleHogNormalizer:

    @staticmethod
    def normalize(findings: list[SecretFinding]) -> list[UnifiedFinding]:
        normalized = []

        for f in findings:
            unified = UnifiedFinding(
                source="trufflehog",
                category="secret",
                severity="critical",
                confidence="high",
                identifier=str(f.secret_type),
                message=f.message or "secret found",
                file_path=f.file_path,
                line_start=f.line_start,
                line_end=f.line_end,
            )

            normalized.append(unified)

        return normalized
