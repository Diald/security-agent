import subprocess
import json
import os

class BanditRunner:
    def run(self, repo_path: str) -> dict:
        # Check if the path actually exists before starting
        if not os.path.exists(repo_path):
            print(f"[!] Path does not exist: {repo_path}")
            return {"results": []}

        cmd = [
            "bandit",
            "-r", repo_path,
            "-f", "json",
            "-q",
            "--exit-zero"  # Ensures return code is 0 even if bugs are found
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                # shell=False is generally safer unless bandit isn't in your PATH
                shell=False, 
                encoding="utf-8",
                errors="replace"
            )
        except FileNotFoundError:
            raise RuntimeError(
                "Bandit is not installed or not found in your PATH. "
                "Try running 'pip install bandit'."
            )
            
        output = result.stdout.strip()
        if not output:
            if result.stderr:
                print(f"[!] Bandit STDERR: {result.stderr}")
            return {"results": []}

        try:
            return json.loads(output)
        except json.JSONDecodeError as e:
            # Sometimes Bandit prints non-JSON warnings before the JSON block
            # This identifies where the actual JSON starts
            if "{" in output:
                try:
                    clean_json = output[output.index("{"):]
                    return json.loads(clean_json)
                except:
                    pass
            
            raise RuntimeError(
                f"Bandit produced invalid JSON.\nSTDOUT: {output}"
            ) from e