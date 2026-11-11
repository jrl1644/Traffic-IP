#!/usr/bin/env python3
"""Rebuild public/index.html from the app source (ip-devices.html) for standalone use."""
import pathlib, re, sys
src = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "app-source.html").read_text()
marker = "\n<script>\n"   # the app's single inline script block
assert src.count(marker) == 1, "expected exactly one inline <script> block in the app source"
out = src.replace(marker, '\n<script src="/standalone.js"></script>\n<script>\n')
# app icon for tabs, bookmarks and "Add to Home Screen" (served by the server; follows the custom icon)
head_tags = """<link rel="icon" type="image/png" href="/favicon.png">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/manifest.webmanifest">
<meta name="theme-color" content="#1f6f4a">
<meta name="apple-mobile-web-app-title" content="Traffic-IP">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
"""
assert out.count("</head>") == 1
out = out.replace("</head>", head_tags + "</head>")
pathlib.Path(__file__).with_name("public").joinpath("index.html").write_text(out)
print("public/index.html written")
