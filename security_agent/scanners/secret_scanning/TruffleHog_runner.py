import subprocess
import json
import os

class TruffleHogRunner:
    def run(self, repo_path: str) -> dict:
        if not os.path.exists(repo_path):
            return {"results": []}

        print(f"[*] Scanning for secrets in: {repo_path}...")

        cmd = [
            "trufflehog", "filesystem", repo_path,
            "--json", "--no-verification",
            "--exclude-files", r"(\.git|node_modules|\.venv|__pycache__|\.pytest_cache|dist|build).*",
            "--max_depth", "8",
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
            raise RuntimeError("TruffleHog not found. Is it in your PATH?")

        # Logging stderr for debugging if needed
        if result.returncode not in (0, 1):
             # TruffleHog often writes its internal errors to stderr
             raise RuntimeError(f"TruffleHog error: {result.stderr}")

        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                # TruffleHog emits one JSON object per line
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        print(f"[+] Secrets scan complete. Found {len(findings)} potential secrets.")
        return {"results": findings}