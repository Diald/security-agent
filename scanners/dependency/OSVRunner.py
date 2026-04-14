import subprocess
import json
import os

class OSVRunner:
    def run(self, repo_path: str) -> dict:
        """
        Runs osv-scanner with optimizations for speed and feedback.
        """
        # 1. Check if path exists to avoid pointless subprocess calls
        if not os.path.exists(repo_path):
            return {"results": []}

        print(f"[*] Starting OSV scan on: {repo_path}...")
        print(f"[*] (This may take a minute for large repositories)")

        cmd = [
            "osv-scanner",
            "scan",
            "--recursive",
            "--format", "json",
            repo_path
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace"
            )
        except FileNotFoundError:
            raise RuntimeError("osv-scanner not found. Is it installed and in your PATH?")

        stderr = result.stderr.lower()

        if "no package sources found" in stderr:
            print("[!] No dependency manifests found. Skipping.")
            return {"results": []}

        if result.returncode not in (0, 1):
            raise RuntimeError(
                f"OSV-Scanner failed with exit code {result.returncode}.\n"
                f"STDERR: {result.stderr}"
            )

        if not result.stdout.strip():
            return {"results": []}

        try:
            data = json.loads(result.stdout)
            print(f"[+] Scan complete. Found {len(data.get('results', []))} results.")
            return data
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"OSV-Scanner produced invalid JSON.\nSTDOUT: {result.stdout}"
            ) from e