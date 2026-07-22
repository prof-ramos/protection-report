#!/usr/bin/env python3
"""
Protection Report Generator — legacy CLI entrypoint.
=================================================================================
This file now delegates to the modular protection_report package.

Usage:
    python3 protection_report.py <maigret_json_file> [--email <email>]
    python3 protection_report.py --username <username> [--email <email>]
"""

import sys
from pathlib import Path

# Ensure package is importable from this directory
sys.path.insert(0, str(Path(__file__).parent))

from protection_report.__main__ import main

if __name__ == "__main__":
    main()
