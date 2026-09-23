"""Attach the upstream and Acorn license notices to each freshly built release."""
from pathlib import Path
from zipfile import ZipFile

root = Path(__file__).resolve().parent
archive_path = root / "dist/plugin_package.zip"
entries = {
    "LICENSE": root / "../../LICENSE",
    "MERGE-NOTES.md": root / "MERGE-NOTES.md",
    "ACORN-LICENSE": root / "packages/backend/node_modules/acorn/LICENSE",
}
with ZipFile(archive_path, "a") as archive:
    existing = set(archive.namelist())
    for name, source in entries.items():
        if name not in existing:
            archive.write(source, name)
    assert archive.testzip() is None
print(f"Release notices verified: {archive_path}")
