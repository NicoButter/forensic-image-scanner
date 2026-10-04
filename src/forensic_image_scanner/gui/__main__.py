"""Allow running the GUI as a module: python -m forensic_image_scanner.gui"""

from forensic_image_scanner.gui.app import main

if __name__ == "__main__":
    raise SystemExit(main())
