#!/usr/bin/env python3
"""
weblog_hunter.py - Backwards compatibility wrapper

This file maintains backwards compatibility with the original weblog_hunter.py script.
All functionality has been moved to the weblog_hunter package.

For new code, use:
    from weblog_hunter.__main__ import main
    
Or run directly:
    python -m weblog_hunter
    weblog-hunter (if installed via pip)
"""

import sys
import warnings

# Use FutureWarning to ensure users see the migration message
warnings.warn(
    "Running weblog_hunter.py directly is deprecated. "
    "Please use 'python -m weblog_hunter' or 'weblog-hunter' instead.",
    FutureWarning,
    stacklevel=2
)

# Import and run the new main function
try:
    from weblog_hunter.__main__ import main
except ImportError as e:
    print(
        f"Error: Could not import weblog_hunter package: {e}\n"
        "Please ensure the package is installed correctly.",
        file=sys.stderr
    )
    sys.exit(1)

if __name__ == "__main__":
    sys.exit(main())
