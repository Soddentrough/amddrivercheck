#!/usr/bin/env python3
"""
package_release.py - Cross-Platform Release Packaging for DriverCheck

Packages runtime scripts, modules, launchers, and documentation into a clean,
distributable ZIP archive with SHA256 checksum calculation.
"""

import argparse
import hashlib
import os
import shutil
import zipfile
from pathlib import Path


def calculate_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().upper()


def main():
    parser = argparse.ArgumentParser(description="Package DriverCheck Release")
    parser.add_argument("--version", default="4.4.0", help="Release version tag (e.g. 4.4.0)")
    args = parser.parse_args()

    version = args.version.lstrip("v")
    root_dir = Path(__file__).resolve().parent.parent
    dist_dir = root_dir / "dist"
    stage_name = f"drivercheck-v{version}"
    stage_dir = dist_dir / stage_name
    zip_path = dist_dir / f"{stage_name}.zip"

    print("=" * 72)
    print(f"  BUILDING DRIVERCHECK RELEASE PACKAGE (v{version})")
    print("=" * 72)
    print()

    # Clean previous build artifacts
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    if zip_path.exists():
        zip_path.unlink()

    stage_dir.mkdir(parents=True, exist_ok=True)
    print("Staging files...")

    # Root files to include
    root_files = [
        "Analyze-LatestCrash.ps1",
        "Get-GPUDriverDiagnostics.ps1",
        "Run-Diagnostics.bat",
        "README.md",
        "QUICKSTART.txt",
        "run.ps1",
    ]

    for rf in root_files:
        src = root_dir / rf
        if src.exists():
            dest = stage_dir / rf
            shutil.copy2(src, dest)
            print(f"  + Staged: {rf}")
        else:
            print(f"  [!] Missing expected root file: {rf}")

    # Copy scripts directory (including modules)
    scripts_src = root_dir / "scripts"
    scripts_dest = stage_dir / "scripts"
    shutil.copytree(
        scripts_src,
        scripts_dest,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.py", "package_release.py", "test_*.py", "verify_scripts.py")
    )
    print("  + Staged: scripts/ directory and modules")

    # Compress archive (flatten so items inside stage_dir are at archive root)
    print("\nCompressing release archive...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in stage_dir.rglob("*"):
            if file_path.is_file():
                arcname = file_path.relative_to(stage_dir)
                zf.write(file_path, arcname)

    # Clean staging directory
    shutil.rmtree(stage_dir)

    # Calculate SHA256 Checksum & Size
    sha256 = calculate_sha256(zip_path)
    size_kb = round(zip_path.stat().st_size / 1024, 2)

    print()
    print("=" * 72)
    print("  BUILD COMPLETE!")
    print("=" * 72)
    print(f"  Package: {zip_path}")
    print(f"  Size:    {size_kb} KB")
    print(f"  SHA256:  {sha256}")
    print("=" * 72)
    print()

    # Also write a checksum file for convenience
    checksum_file = dist_dir / f"{stage_name}.zip.sha256"
    checksum_file.write_text(f"{sha256}  {zip_path.name}\n")
    print(f"Checksum written to: {checksum_file}")


if __name__ == "__main__":
    main()
