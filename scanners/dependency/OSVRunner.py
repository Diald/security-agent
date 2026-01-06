import subprocess
import json


class OSVRunner:
    def run(self, repo_path: str) -> dict:
        """
        Runs osv-scanner against a repository directory and returns raw JSON output.

        Behavior:
        - Skips cleanly if no dependency manifests are found
        - Returns empty results for valid 'no dependency' cases
        - Raises only on real execution failures
        """

        cmd = [
            "osv-scanner",
            "scan",
            "--recursive",
            "--format", "json",
            repo_path
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        stderr = result.stderr.lower()

        # --- CASE 1: No dependencies present (VALID, NON-FATAL) ---
        if "no package sources found" in stderr:
            return {"results": []}

        # osv-scanner exit codes:
        # 0 → no vulnerabilities
        # 1 → vulnerabilities found
        if result.returncode not in (0, 1):
            raise RuntimeError(
                f"OSV-Scanner failed.\nSTDERR:\n{result.stderr}"
            )

        # --- CASE 2: Valid execution but no output ---
        if not result.stdout.strip():
            return {"results": []}

        # --- CASE 3: Normal JSON output ---
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError(
                "OSV-Scanner produced invalid JSON.\n"
                f"STDOUT:\n{result.stdout}\n\n"
                f"STDERR:\n{result.stderr}"
            ) from e