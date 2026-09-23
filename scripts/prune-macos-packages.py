#!/usr/bin/env python3
"""Keep the two newest FortiClient macOS arm64 packages and checksums."""
import re
import sys
from pathlib import Path

pattern = re.compile(r"forti-client-.+-(\d{8}\.\d{6})-macos\d+-arm64\.pkg$")
root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).resolve().parents[1] / "dist"
packages = [(match.group(1), path) for path in root.iterdir()
            if (match := pattern.match(path.name))]
for _, path in sorted(packages, reverse=True)[2:]:
    path.unlink()
    path.with_name(path.name + ".sha256").unlink(missing_ok=True)
    print(f"Removed old installer: {path.name}")
