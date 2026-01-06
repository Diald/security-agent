from typing import List
from core.models import DependencyFinding


class OSVParser:
    def parse(self, raw: dict) -> List[DependencyFinding]:
        findings: List[DependencyFinding] = []

        # OSV scanner structure:
        # {
        #   "results": [
        #       {
        #           "source": {...},
        #           "packages": [
        #               {
        #                   "package": {...},
        #                   "vulnerabilities": [...]
        #               }
        #           ]
        #       }
        #   ]
        # }

        for result in raw.get("results", []):
            for pkg in result.get("packages", []):

                package_info = pkg.get("package", {})
                ecosystem = package_info.get("ecosystem")
                package_name = package_info.get("name")
                installed_version = package_info.get("version")

                for vuln in pkg.get("vulnerabilities", []):

                    vuln_id = vuln.get("id")
                    summary = vuln.get("summary", "")

                    severity = None
                    for sev in vuln.get("severity", []):
                        # Prefer CVSS if present
                        if sev.get("type") == "CVSS_V3":
                            severity = sev.get("score")
                            break

                    affected_range = None
                    fixed_version = None

                    for affected in vuln.get("affected", []):
                        for r in affected.get("ranges", []):
                            if r.get("type") == "ECOSYSTEM":
                                events = r.get("events", [])
                                introduced = None
                                fixed = None

                                for e in events:
                                    if "introduced" in e:
                                        introduced = e["introduced"]
                                    if "fixed" in e:
                                        fixed = e["fixed"]

                                if introduced or fixed:
                                    affected_range = f"{introduced or '*'} → {fixed or 'unfixed'}"
                                    fixed_version = fixed

                    references = [
                        ref.get("url")
                        for ref in vuln.get("references", [])
                        if ref.get("url")
                    ]

                    findings.append(
                        DependencyFinding(
                            tool="osv-scanner",
                            ecosystem=ecosystem,
                            package_name=package_name,
                            installed_version=installed_version,
                            fixed_version=fixed_version,
                            vulnerability_id=vuln_id,
                            severity=severity,
                            summary=summary,
                            affected_range=affected_range,
                            references=references,
                        )
                    )

        return findings