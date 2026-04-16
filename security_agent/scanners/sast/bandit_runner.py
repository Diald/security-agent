import subprocess
import json
import os
import time
import glob
from concurrent.futures import ProcessPoolExecutor, as_completed


def _scan_files_chunk(args: tuple) -> dict:
    """Top-level function (required for pickling with ProcessPoolExecutor)."""
    file_chunk, excluded_paths = args

    cmd = [
        "bandit",
        "-f", "json",
        "-q",
        "--exit-zero",
        "-x", ",".join(excluded_paths),
    ] + file_chunk

    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    output = result.stdout.strip()
    if not output:
        return {"results": [], "errors": [], "metrics": {}}

    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"results": [], "errors": [], "metrics": {}}


class BanditRunner:
    EXCLUDED = {
        ".git", ".venv", "env", "venv", "node_modules", "vendor",
        "__pycache__", ".pytest_cache", "dist", "build", "reports",
    }

    def __init__(self, workers: int = 4, chunk_size: int = 50):
        self.workers = workers        # parallel bandit processes
        self.chunk_size = chunk_size  # files per process

    def _collect_files(self, repo_path: str) -> list[str]:
        """Collect all .py files, skipping excluded directories."""
        py_files = []
        abs_repo = os.path.abspath(repo_path)

        for root, dirs, files in os.walk(abs_repo):
            # Prune excluded dirs in-place so os.walk skips them entirely
            dirs[:] = [d for d in dirs if d not in self.EXCLUDED]

            for f in files:
                if f.endswith(".py"):
                    py_files.append(os.path.join(root, f))

        return py_files

    def _chunk(self, files: list[str]) -> list[list[str]]:
        return [files[i:i + self.chunk_size] for i in range(0, len(files), self.chunk_size)]

    def _merge_results(self, results: list[dict]) -> dict:
        merged = {"results": [], "errors": [], "metrics": {}}
        for r in results:
            merged["results"].extend(r.get("results", []))
            merged["errors"].extend(r.get("errors", []))
        return merged

    def run(self, repo_path: str) -> dict:
        if not os.path.exists(repo_path):
            print(f"[!] Path does not exist: {repo_path}")
            return {"results": []}

        abs_excluded = [
            os.path.join(os.path.abspath(repo_path), ex)
            for ex in self.EXCLUDED
        ]

        start = time.perf_counter()

        py_files = self._collect_files(repo_path)
        if not py_files:
            print("[!] No Python files found.")
            return {"results": []}

        chunks = self._chunk(py_files)
        print(f"[*] Scanning {len(py_files)} files across {len(chunks)} chunks with {self.workers} workers...")

        chunk_args = [(chunk, abs_excluded) for chunk in chunks]
        chunk_results = []

        try:
            with ProcessPoolExecutor(max_workers=self.workers) as executor:
                futures = {executor.submit(_scan_files_chunk, arg): i for i, arg in enumerate(chunk_args)}
                for future in as_completed(futures):
                    try:
                        chunk_results.append(future.result())
                    except Exception as e:
                        print(f"[!] Chunk failed: {e}")
        except FileNotFoundError:
            raise RuntimeError(
                "Bandit is not installed or not found in PATH. "
                "Run: pip install bandit"
            )

        merged = self._merge_results(chunk_results)
        duration = time.perf_counter() - start
        print(f"[*] Scan complete in {duration:.2f}s — {len(merged['results'])} issues found.")
        return merged