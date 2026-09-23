"""Attach notices to the current JS Analyzer Plus release."""
from pathlib import Path
import runpy

runpy.run_path(str(Path(__file__).resolve().parent / "plugins/js-analyzer-plus/package-notices.py"), run_name="__main__")
