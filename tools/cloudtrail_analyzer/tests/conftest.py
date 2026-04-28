from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))
SAMPLE_DIR = REPO_ROOT / "tools" / "cloudtrail_analyzer" / "sample_data"
