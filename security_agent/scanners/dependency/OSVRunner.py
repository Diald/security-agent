import subprocess
import json
import os


class OSVRunner:
    def run(self, repo_path: str) -> dict:
        if not os.path.exists(repo_path):
            return {"results": []}

        print(f"[*] Starting OSV scan on: {repo_path}...")

        # First check if there are any dependency manifests worth scanning
        manifest_files = [
            "requirements.txt", "requirements-dev.txt", "Pipfile", "Pipfile.lock",
            "pyproject.toml", "setup.py", "setup.cfg",  # Python
            "package.json", "package-lock.json", "yarn.lock",  # Node
            "go.mod", "go.sum",                                 # Go
            "Cargo.toml", "Cargo.lock",                        # Rust
            "pom.xml", "build.gradle",                         # Java
        ]

        found_manifests = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in {".git", ".venv", "venv", "node_modules", "__pycache__"}]
            for f in files:
                if f in manifest_files:
                    found_manifests.append(os.path.join(root, f))

        if not found_manifests:
            print("[!] No dependency manifests found (requirements.txt, package.json, etc). Skipping OSV scan.")
            return {"results": []}

        print(f"[*] Found {len(found_manifests)} manifest(s) to scan:")
        for m in found_manifests:
            print(f"    - {m}")

        # Use --format json and --recursive, drop --offline and --no-resolve
        cmd = [
            "osv-scanner",
            "--recursive",
            "--format", "json",
            repo_path,
        ]

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError:
            raise RuntimeError(
                "osv-scanner not found. Install it from: "
                "https://github.com/google/osv-scanner/releases"
            )

        stderr_lower = result.stderr.lower()

        # OSV returns exit code 1 when vulnerabilities ARE found (not an error)
        if result.returncode not in (0, 1):
            print(f"[!] OSV-Scanner stderr: {result.stderr}")
            raise RuntimeError(
                f"OSV-Scanner failed with exit code {result.returncode}.\n"
                f"STDERR: {result.stderr}"
            )

        stdout = result.stdout.strip()
        if not stdout:
            print("[!] OSV-Scanner returned no output.")
            if result.stderr:
                print(f"[!] STDERR: {result.stderr}")
            return {"results": []}

        try:
            data = json.loads(stdout)
            count = len(data.get("results", []))
            print(f"[+] Scan complete. Found {count} result(s).")
            return data
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"OSV-Scanner produced invalid JSON.\nSTDOUT: {stdout}"
            ) from e