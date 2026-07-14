"""PyInstaller entry point for the standalone binary.

The console-script shim pip generates is not analyzable by PyInstaller;
this plain script gives it a static import root.
"""

from openstack_janitor.cli import main

if __name__ == "__main__":
    main()
