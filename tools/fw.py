from pathlib import Path
import sys

platform = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(platform))
from fwplatform.cli import main  # noqa: E402

raise SystemExit(main(sys.argv[1:]))

