import os
import shutil
import uuid
import time
import stat
from git import Repo

TMP_DIR = "tmp"


class RepoManager:

    @staticmethod
    def clone_repo(repo_url: str) -> str:
        repo_id = str(uuid.uuid4())
        path = os.path.join(TMP_DIR, repo_id)

        os.makedirs(TMP_DIR, exist_ok=True)

        if os.path.exists(path):
            RepoManager.cleanup(path)

        repo = Repo.clone_from(repo_url, path, depth=1)

        # CRITICAL for Windows
        repo.close()

        return path

    @staticmethod
    def cleanup(path: str, retries: int = 5):
        def onerror(func, p, exc_info):
            os.chmod(p, stat.S_IWRITE)
            func(p)

        for _ in range(retries):
            try:
                shutil.rmtree(path, onerror=onerror)
                return
            except PermissionError:
                time.sleep(0.5)

        raise RuntimeError(f"Failed to delete {path}")
