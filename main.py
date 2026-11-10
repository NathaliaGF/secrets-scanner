#!/usr/bin/env python3
"""Backwards-compatible entry point: ``python main.py --dir .`` (same as the ``secrets-scanner`` command)."""

from secrets_scanner.cli import main

if __name__ == "__main__":
    main()
