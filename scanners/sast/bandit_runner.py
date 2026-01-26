import subprocess
import json


class BanditRunner:
    def run(self, repo_path: str) -> dict:
        cmd = [
            "bandit",
            "-r", repo_path,
            "-f", "json",
            "-q",
            "--exit-zero"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True,
            encoding="utf-8",
            errors="replace"
        )

        # At this point:
        # - stdout is either valid JSON or empty JSON
        # - stderr is irrelevant noise (already suppressed)

        if not result.stdout.strip():
            return {"results": []}

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"Bandit JSON parsing failed.\n"
                f"STDOUT:\n{result.stdout}\n\n"
                f"STDERR:\n{result.stderr}"
            ) from e
