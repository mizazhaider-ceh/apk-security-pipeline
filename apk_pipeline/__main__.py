"""Allow: python3 -m apk_pipeline scan app.apk --explain"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
