# SPDX-License-Identifier: AGPL-3.0-only
"""Launch the source-shaped release from any working directory."""

import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from journeon.runtime import main  # noqa: E402

raise SystemExit(main())
