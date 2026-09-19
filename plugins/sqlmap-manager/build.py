"""Package source files only. Does not import or run plugin code or sqlmap."""
from pathlib import Path
import zipfile

root = Path(__file__).resolve().parent
destination = root / "dist" / "plugin_package.zip"
destination.parent.mkdir(exist_ok=True)
with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
    for relative in ("manifest.json", "backend/script.js", "frontend/script.js", "frontend/style.css"):
        archive.write(root / relative, relative)
print(destination)
