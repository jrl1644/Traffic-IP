#!/usr/bin/env python3
"""Rebuild public/index.html from the app source (ip-devices.html) for standalone use."""
import pathlib, re, sys
src = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "app-source.html").read_text()
marker = "<script>\nconst DEFAULT_TYPES"
assert src.count(marker) == 1, "app script marker not found"
out = src.replace(marker, '<script src="/standalone.js"></script>\n' + marker)
pathlib.Path(__file__).with_name("public").joinpath("index.html").write_text(out)
print("public/index.html written")
