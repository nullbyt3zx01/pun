# Changelog

## 0.2.0 — Cookie Inspector + Advanced Intelligence

- Added local-only Cookie Inspector for request `Cookie` and response `Set-Cookie` values.
- Added bounded decoding for Base64, Base64URL, URL-percent, hex, gzip-compressed Base64 and JWT header/payload; added JSON field discovery.
- Added hash-family recognition (MD5-like, SHA-1-like, SHA-256-like, SHA-512-like), plus offline one-candidate verification (NOT decryption or cracking).
- Added keyed HMAC session fingerprints independent of MCP bridge tokens; raw cookie and decoded values stay in Burp UI.
- Added four MCP tools: `analyze_pun_deep`, `inspect_cookie_metadata`, `correlate_cookie_sessions`, `observed_workflow_graph`.
- Added role-endpoint matrix, hypothesis scoring, workflow-order review hints and session rotation review hints.
- Added Python tests for encoded cookies, JWT redaction, MD5/SHA, invalid input and deep intelligence; added JUnit tests for native Java decoder.
- Preserved manual replay approval, scope allowlists and disabled mutation replays by default.

## 0.1.0 — Initial MVP

- Burp traffic capture and role profiles; AuthGraph, LogicHunter; replay queue; MCP server and local lab.
