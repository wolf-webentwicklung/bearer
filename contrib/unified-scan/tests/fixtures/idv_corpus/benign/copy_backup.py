import datetime
import shutil
import sys
from pathlib import Path


def backup(source: str, target_root: str) -> Path:
    stamp = datetime.date.today().isoformat()
    target = Path(target_root) / f"backup-{stamp}"
    shutil.copytree(source, target)
    return target


if __name__ == "__main__":
    print(backup(sys.argv[1], sys.argv[2]))
