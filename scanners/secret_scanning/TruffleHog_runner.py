import subprocess
import json


class TruffleHogRunner:
    def run(self, repo_path: str) -> dict:
        """
        Runs TruffleHog against a local repository directory and returns raw JSON output.

        Assumptions:
        - trufflehog is installed and available on PATH
        - repo_path is a local filesystem path
        """

        cmd = [
            "trufflehog",
            "filesystem",
            repo_path,
            "--json"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        # TruffleHog exit codes:
        # 0 → no secrets found
        # 1 → secrets found
        if result.returncode not in (0, 1):
            raise RuntimeError(
                f"TruffleHog failed.\nSTDERR:\n{result.stderr}"
            )

        # TruffleHog emits **newline-delimited JSON**
        # Each line is a separate finding
        findings = []

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                # Skip malformed lines but do not crash the scan
                continue

        return {"results": findings}