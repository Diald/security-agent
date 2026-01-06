from typing import List
from core.models import SecretFinding
import hashlib


class TruffleHogParser:
    def parse(self, raw: dict) -> List[SecretFinding]:
        findings: List[SecretFinding] = []

        for item in raw.get("results", []):

            # --- Extract metadata safely ---
            detector = item.get("DetectorName")
            secret_type = str(item.get("DetectorType") or detector or "unknown")

            source_metadata = item.get("SourceMetadata", {})
            file_path = source_metadata.get("Data", {}).get("Filesystem", {}).get("file")

            line = source_metadata.get("Data", {}).get("Filesystem", {}).get("line")

            verified = bool(item.get("Verified", False))

            # --- Stable fingerprint (critical for deduplication) ---
            fingerprint_source = f"{detector}:{file_path}:{line}"
            fingerprint = hashlib.sha256(
                fingerprint_source.encode("utf-8", errors="ignore")
            ).hexdigest()

            # --- Severity & confidence logic (deterministic) ---
            if verified:
                severity = "critical"
                confidence = "high"
            else:
                severity = "medium"
                confidence = "medium"

            findings.append(
                SecretFinding(
                    tool="trufflehog",
                    secret_type=secret_type,
                    detector=detector,
                    file_path=file_path or "unknown",
                    line_start=line,
                    line_end=line,
                    fingerprint=fingerprint,
                    verified=verified,
                    severity=severity,
                    confidence=confidence,
                    message=item.get("Description"),
                )
            )

        return findings