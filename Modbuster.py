#!/usr/bin/env python3
"""Launch the Modbuster GUI from the project root."""

import sys
import traceback
from pathlib import Path

# Ensure project root is on path
root = Path(__file__).resolve().parent
if str(root) not in sys.path:
    sys.path.insert(0, str(root))

if __name__ == "__main__":
    try:
        from modbuster.gui import main
        main()
    except Exception as e:
        traceback.print_exc()
        # Keep console open so user can read the error
        try:
            input("\nPress Enter to close...")
        except Exception:
            pass
        sys.exit(1)
