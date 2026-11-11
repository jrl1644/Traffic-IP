#!/usr/bin/env python3
"""Rebuild public/index.html from the app source (ip-devices.html) for standalone use."""
import pathlib, re, sys
src = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "app-source.html").read_text()
marker = "\n<script>\n"   # the app's single inline script block
assert src.count(marker) == 1, "expected exactly one inline <script> block in the app source"
out = src.replace(marker, '\n<script src="/standalone.js"></script>\n<script>\n')
pathlib.Path(__file__).with_name("public").joinpath("index.html").write_text(out)
print("public/index.html written")
