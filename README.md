<p align="center">
  <img src="assets/pun-logo.png" alt="Pun logo — orange boxing glove mascot" width="280" />
</p>

<h1 align="center">Pun</h1>

<p align="center"><strong>Burp Suite + MCP | AuthGraph + LogicHunter + Cookie Inspector + Deep Intelligence</strong></p>

Pun is an open-source-ready experimental Burp extension and local MCP server for *authorized bug bounty and application-security testing*. It watches **in-scope traffic**, suggests **ownership / role-boundary tests**, infers **business workflows**, and queues **one-request-at-a-time replays** which a human must approve inside Burp.

**Version:** 0.2.0 (experimental source release)

> ⚠️ This is not an autonomous vulnerability scanner. A `200 OK`, matching response hash, or inferred workflow is NOT sufficient to claim IDOR or business logic exploitation. Confirm actual ownership and business impact with your own authorized test accounts.

## Architecture

```text
MCP client (Claude / Cursor / MCP Inspector)
            | MCP stdio
            v
 Python MCPServer (mcp 2.x)
     AuthGraph / LogicHunter / Deep Intelligence / reports
            | HTTP + Bearer token (loopback only)
            v
 Burp Montoya Java Extension (Pun tab)
   metadata capture (in scope + exact host allowlist)
   local in-memory test session profiles
   replay approval queue -> human clicks Approve
            |
       Burp HTTP API
            v
 Authorized test server ONLY
```

### What is implemented now?

| Component | MVP function | Limits |
|---|---|---|
| Traffic Collector | In-scope + exact-host allowlist, 400 latest observations | No file-backed history, no import/backfill |
| Role Profiles | Session names + Cookie + Authorization stored in Java memory | Create roles before capturing for accurate labels |
| AuthGraph | Endpoint/role inventory + ownership candidate ranking | Hypotheses only; no automatic IDOR verdict |
| Deep Intelligence | Role–endpoint matrix, risk prioritization, session correlation and suspicious action ordering | Heuristics only, not confirmed bugs |
| Cookie Inspector | Local Base64/Base64URL/URL/hex/JWT/JSON/GZIP inspection + hash-family detection | Raw/decoded cookies visible only in local Burp UI |
| LogicHunter | Workflow grouping and step-skip/reorder/duplicate hypotheses | Heuristic; no automatic multi-step state engine |
| Replay Engine | Queue individual requests; manual approve/deny inside Burp | Unsafe HTTP verbs OFF by default |
| Replay Analysis | Status, response hash and JSON field-name comparison | No raw response body exported to MCP |
| Reports | Markdown candidate evidence | Requires human review before submission |
| MCP Server | 14 tools via Python MCP SDK v2, stdio | Python 3.11+; SDK needs installation |

## Requirements

- Burp Suite with the Montoya API (a recent Burp release compatible with Montoya `2026.7`).
- JDK **21** and Gradle 8+ (to build Burp JAR).
- Python **3.11+**.
- Internet access to install build dependencies on your machine.

## Quick start: Linux and Windows

Pun has **two local components**: (1) the Java Burp Suite extension, and (2) the Python **stdio MCP server** launched automatically by Codex, Claude Code, or another MCP client. You do **not** start a public MCP web server. The Python MCP server connects to the Burp bridge on `http://127.0.0.1:8765` with a token copied from Burp's **Pun** tab.

| Step | Linux | Windows |
|---|---|---|
| Build Burp JAR | `cd burp-extension && gradle clean test jar` | Same command in PowerShell after `cd .\burp-extension` |
| Python virtualenv | `python3 -m venv .venv` | `py -3.11 -m venv .venv` |
| Install Pun MCP | `.venv/bin/python -m pip install -e ./python` | `.\.venv\Scripts\python.exe -m pip install -e .\python` |
| Attach to Burp | Extensions → Installed → Add → Java | Same |
| Connect Codex | See [Codex on Linux](#4-connect-openai-codex-cli--ide) | See [Codex on Windows](#codex-on-windows-powershell) |

> All paths below assume you extracted the archive so that the repository root contains `README.md`, `burp-extension/`, and `python/`. Replace example paths with **your own absolute paths**. Burp and your local MCP client must reach the **same machine's** loopback bridge; WSL, containers and remote Codex hosts need special network consideration.

## 1. Linux setup (Ubuntu / Debian / Fedora / Arch)

### 1.1 Install prerequisites

**Ubuntu 24.04+ / compatible Debian releases** (package availability varies by release):

```bash
sudo apt update
sudo apt install -y openjdk-21-jdk python3 python3-venv python3-pip curl unzip
```

**Fedora**:

```bash
sudo dnf install java-21-openjdk-devel python3 python3-pip gradle
```

**Arch Linux**:

```bash
sudo pacman -Syu --needed jdk21-openjdk python python-pip gradle
```

Install **Gradle 8.5+** (or any newer version supporting Java 21) if your distribution's Gradle is too old. The repository currently has **no Gradle Wrapper**; follow the [official Gradle installation guide](https://docs.gradle.org/current/userguide/installation.html) or use [SDKMAN!](https://sdkman.io/) on Linux. In particular, older Ubuntu/Debian `apt install gradle` releases may be unsuitable.

Verify all tools before building:

```bash
java -version           # JDK 21
python3 --version       # Python 3.11+
gradle --version        # compatible Gradle
```

If your Linux distro defaults to a different Java, select JDK 21 (`JAVA_HOME` / `update-alternatives`) or configure the Gradle toolchain. If `python3` is older than 3.11, install a supported interpreter and use it to create the venv.

### 1.2 Build the Burp Suite Java extension

From the Pun repository root:

```bash
cd /absolute/path/to/Pun
cd burp-extension
gradle clean test jar
```

Expected output if the build succeeds:

```text
burp-extension/build/libs/pun-burp-0.2.0.jar
```

The path above is relative to the repository root. This is **not** a prebuilt JAR: you must build it with Montoya/Gson dependencies available from Maven Central. This release's Java code has not been verified inside a real Burp Suite installation.

### 1.3 Load Pun into Burp and enable the local bridge

1. Open **Burp Suite → Extensions → Installed → Add**, select **Java**, and choose the built `pun-burp-0.2.0.jar`.
2. Open the new **Pun** tab. In **Burp → Target → Scope**, add **only targets you are authorized to test**.
3. In **Pun → Exact test hosts**, enter the **same exact hosts** and click **Save allowed hosts**. An empty list blocks capture and replay; this is intentional. For the bundled local lab, use `127.0.0.1`.
4. Configure your own test role/session profiles such as `userA` and `userB`, if needed; session secrets remain local in the Java process.
5. Capture a few requests via Burp Proxy / Repeater. Pun tracks **new** matching traffic; it does not import existing Proxy History.
6. Copy the **Bridge token** from the Pun tab. Burp listens on `127.0.0.1:8765` **only while the extension is loaded**, with token authentication.

The bridge is *not* a public MCP HTTP endpoint; do **not** add `http://127.0.0.1:8765` as a remote MCP URL in Codex or Claude.

### 1.4 Install the local Python MCP package

Open a **new terminal** at the repository root (not inside `burp-extension`):

```bash
cd /absolute/path/to/Pun
python3 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -e ./python
./.venv/bin/python -c 'from pun_mcp.server import mcp; print("Pun MCP Python import OK")'
```

Do not run `python -m pun_mcp.server` in the foreground as a normal HTTP server. The stdio MCP process is launched by your AI client after registration. Also avoid `sudo pip install`; use the isolated `.venv`.

## 2. Windows setup (PowerShell)

Install **JDK 21**, **Gradle 8.5+**, and **Python 3.11+**, then from the Pun repository root (example `C:\Tools\Pun`):

```powershell
cd C:\Tools\Pun
cd .\burp-extension
gradle clean test jar
cd ..
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .\python
.\.venv\Scripts\python.exe -c "from pun_mcp.server import mcp; print('Pun MCP Python import OK')"
```

Load `C:\Tools\Pun\burp-extension\build\libs\pun-burp-0.2.0.jar` in **Burp → Extensions → Installed → Add**, configure **Target Scope**, **Pun Exact test hosts**, and your test roles as described above. Copy the bridge token from Pun for the MCP client below. In Windows, use **PowerShell**, not Linux Bash syntax.

## 3. Replay safety and permission policy

- AI tools may **queue** one replay, but **cannot execute it automatically**. Burp's **Pun → Replay queue** requires manual approval for every test.
- Only `GET`, `HEAD`, and `OPTIONS` are enabled by default. State-changing verbs require an additional toggle **and** per-request approval.
- The selected test role supplies the replacement authentication. Do **not** infer object ownership from a matching HTTP status or response hash; verify with authorized accounts.
- Do not replay payments, refunds, destructive operations, or customer data without explicit program authorization.
- Pun strips common authentication headers before applying a role; unusual credentials embedded in a body are **not rewritten**. Review all queued requests locally.
- Decoded/raw Cookie values are visible **only in the local Burp Cookie Inspector**; the MCP tools expose redacted metadata rather than plaintext secrets.

## 4. Connect OpenAI Codex (CLI + IDE)

Codex CLI and its IDE integration share MCP configuration. Run the registration command **once**, then Codex can launch Pun's Python MCP server whenever needed. You need `codex` installed and signed in first; see [Codex MCP documentation](https://developers.openai.com/codex/mcp).

### Codex on Linux (Bash)

Run this **from the Pun repository root**, after the Java extension has been loaded in Burp:

```bash
cd /absolute/path/to/Pun
PUN_PYTHON="$PWD/.venv/bin/python"
read -r -s -p 'Paste the bridge token from Burp Pun tab: ' PUN_TOKEN; echo

codex mcp add pun \
  --env "PUN_BRIDGE_URL=http://127.0.0.1:8765" \
  --env "PUN_BRIDGE_TOKEN=$PUN_TOKEN" \
  -- "$PUN_PYTHON" -m pun_mcp.server

unset PUN_TOKEN
codex mcp list
```

Then:

```bash
codex
```

Within Codex, run `/mcp` to inspect the active server. Ask it to **call `pun_health`**. A successful initialization alone does **not** prove Burp is connected: `pun_health` needs to return current bridge data.

> The bridge token is saved in your local Codex MCP configuration as an environment value. Do not commit config files containing that value or paste it into prompts, logs or screenshots. Re-register / edit it when the Burp extension restarts, since Pun generates a new token per load.

### Codex on Windows (PowerShell)

```powershell
cd C:\Tools\Pun
$PunPython = (Resolve-Path .\.venv\Scripts\python.exe).Path
$PunToken = Read-Host "Paste the bridge token from Burp Pun tab"

codex mcp add pun `
  --env "PUN_BRIDGE_URL=http://127.0.0.1:8765" `
  --env "PUN_BRIDGE_TOKEN=$PunToken" `
  -- $PunPython -m pun_mcp.server

Remove-Variable PunToken
codex mcp list
```

Launch `codex`, check `/mcp`, and request `pun_health`. In PowerShell, the backtick **must be the last character on its line** (no trailing spaces).

### Alternative: manual Codex configuration

Instead of running `codex mcp add`, edit **`~/.codex/config.toml`** (Linux) or **`%USERPROFILE%\.codex\config.toml`** (Windows) to include:

```toml
[mcp_servers.pun]
command = "/home/YOU/tools/Pun/.venv/bin/python" # Linux: use your absolute path
args = ["-m", "pun_mcp.server"]

[mcp_servers.pun.env]
PUN_BRIDGE_URL = "http://127.0.0.1:8765"
PUN_BRIDGE_TOKEN = "PASTE_TOKEN_FROM_BURP"
```

On Windows, set `command = "C:\\Tools\\Pun\\.venv\\Scripts\\python.exe"` instead. Do **not** create two `[mcp_servers.pun]` entries: merge with any existing config. Protect files containing secrets (for example `chmod 600 ~/.codex/config.toml` on Linux).

### Remove / re-register Pun in Codex

```bash
codex mcp list
codex mcp remove pun
# Then run the appropriate 'codex mcp add pun ...' command again
```

## 5. Connect Claude Code (Linux / macOS / Windows)

Claude Code also supports the same **local stdio server**. With your Pun repository as the current directory, the following is a **Linux Bash** example:

```bash
cd /absolute/path/to/Pun
PUN_PYTHON="$PWD/.venv/bin/python"
read -r -s -p 'Paste Pun bridge token: ' PUN_TOKEN; echo

claude mcp add \
  --env "PUN_BRIDGE_URL=http://127.0.0.1:8765" \
  --env "PUN_BRIDGE_TOKEN=$PUN_TOKEN" \
  --transport stdio \
  pun \
  -- "$PUN_PYTHON" -m pun_mcp.server

unset PUN_TOKEN
claude mcp list
claude mcp get pun
```

Start `claude`, open `/mcp`, and call `pun_health`. On Windows, use the full `C:\Tools\Pun\.venv\Scripts\python.exe` path and PowerShell line continuations instead. See [Claude Code MCP docs](https://code.claude.com/docs/en/mcp) for commands and scopes.

## 6. Cursor, Claude Desktop and other stdio clients

Use the following shape in a client's `mcpServers` JSON (e.g. Cursor's Linux `~/.cursor/mcp.json`, or a supported Claude Desktop installation). **Replace the paths and token:**

```json
{
  "mcpServers": {
    "pun": {
      "command": "/home/YOU/tools/Pun/.venv/bin/python",
      "args": ["-m", "pun_mcp.server"],
      "env": {
        "PUN_BRIDGE_URL": "http://127.0.0.1:8765",
        "PUN_BRIDGE_TOKEN": "PASTE_TOKEN_FROM_BURP"
      }
    }
  }
}
```

On Windows, replace `command` with `C:\\Tools\\Pun\\.venv\\Scripts\\python.exe` (JSON requires escaped backslashes). **Claude Desktop availability and config paths differ by OS**; use the documented config location of your installed client. An MCP client must support **local stdio**, not only remote HTTP.

## 7. Check that Pun is connected

In Codex, Claude or another MCP host, ask:

> Use the `pun` MCP server. First call `pun_health`. Then call `list_roles`, `list_endpoints`, and `analyze_pun_deep` to analyze only currently observed in-scope traffic. Explain hypotheses separately from confirmed findings. Do not queue a replay or send additional HTTP requests without asking me first.

From a **local Linux terminal** you can also verify the authenticated Burp bridge directly (this is a bridge check, not an MCP protocol test):

```bash
read -r -s -p 'Paste Pun bridge token: ' PUN_TOKEN; echo
curl --noproxy '*' -fsS \
  -H "Authorization: Bearer $PUN_TOKEN" \
  http://127.0.0.1:8765/health
unset PUN_TOKEN
```

The output should be JSON from the Pun bridge. Do not paste its token into GitHub issues or public terminal recordings. No request is sent to the target by this health check.

### Troubleshooting

| Symptom | What to check |
|---|---|
| `codex: command not found` / `claude: command not found` | Install the intended AI CLI and confirm it is on your shell's `PATH`. |
| `gradle: command not found` or Java 21 build error | Install compatible Gradle 8.5+ and a JDK 21; check `gradle --version` and `java -version`. |
| `externally-managed-environment` on Linux | Use `.venv/bin/python -m pip` instead of system `pip` or `sudo pip`. |
| `No module named pun_mcp` | Re-run `./.venv/bin/python -m pip install -e ./python` from the Pun repository root. Ensure Codex points to **that exact venv executable**. |
| `No module named mcp`, or SDK import error | Run the install command; make sure a compatible MCP Python SDK is available for your platform and Python version. Check the logged exception before retrying. |
| `pun_health` cannot reach bridge (`Connection refused`) | Burp must be open; Pun JAR must load; the bridge must be listening on `127.0.0.1:8765` on the **same OS / network namespace** as Codex or Claude. |
| `401 Unauthorized` | The configured `PUN_BRIDGE_TOKEN` is outdated; copy the new token from the Pun tab and update/re-register the MCP server. |
| `pun_health` works but no traffic | Set Burp Target Scope **and** Pun Exact test hosts, then generate **new in-scope traffic** after loading Pun. |
| Running Codex in WSL while Burp runs on Windows | WSL and Windows may not share the same `127.0.0.1`. Pun deliberately binds to Windows loopback; **do not expose it to your LAN** as a workaround. Easiest: run Burp and the MCP client both natively on Windows, or both in the same Linux environment. |
| Codex cloud/remote environment cannot reach Pun | A remote MCP process does not share your workstation's localhost. Use local Codex CLI/IDE and a local stdio server for this version of Pun. |

**Security reminder:** Registering a server writes a local configuration, potentially including the bridge token. Never commit such configs or share authentication values. MCP and AI suggestions are hypotheses; replay needs the separate Burp user approval. The Java extension has not yet been fully validated against a real Burp runtime in this delivery environment.

## MCP tools

| Tool | What it does |
|---|---|
| `pun_health` | Get bridge state (allowed hosts, count of traffic, roles and jobs). |
| `list_observed_requests` | Return sanitized metadata, max 100 most recent captured requests. |
| `list_endpoints` | Group observed endpoints and collect input/output key names. |
| `list_roles` | Return test role names, never session secrets. |
| `analyze_authgraph` | Identify likely object-ID / ownership authorization hypotheses. |
| `discover_logic_workflows` | Group likely sequential business actions by host and role. |
| `plan_logic_test` | Plan safe manual skip/reorder/duplicate checks for 2–10 selected requests. |
| `queue_auth_replay` | Queue one replay for explicit approval inside Burp. |
| `replay_status` | Compare baseline and replay metadata conservatively. |
| `draft_evidence_report` | Generate a Markdown evidence draft for a completed job. |
| `analyze_pun_deep` | Role-endpoint matrix, prioritized cross-request hypotheses, workflow gaps and session overview. |
| `inspect_cookie_metadata` | Redacted encodings/JWT claim names/hash-family for a chosen request ID, NO cookie values. |
| `correlate_cookie_sessions` | Correlate cookie equality using per-run keyed HMAC aliases and list JWT review hints. |
| `observed_workflow_graph` | Build an observed action-transition graph without replay. |

### Sample flow

1. `pun_health()` — verify Burp connection and scope.
2. `list_endpoints()` / `analyze_authgraph()` — inspect candidate object-bound routes.
3. `discover_logic_workflows()` / `observed_workflow_graph()` — examine transaction-like sequences.
   `analyze_pun_deep()` — prioritize cross-request authorization and workflow hypotheses.
   `inspect_cookie_metadata("req-12")` — inspect safe cookie metadata (not the actual decoded content).
4. `plan_logic_test(["req-12", "req-15"])` — analyze one candidate workflow.
5. `queue_auth_replay("req-12", "userA", "Compare my test accounts' order ownership")` — **queues only**.
6. **Approve inside Burp**, then `replay_status("job-...")`.
7. If completed, `draft_evidence_report("job-...")`; validate impact independently.

## Run Python tests

```powershell
cd Pun\python
$env:PYTHONPATH = "."
python -m unittest discover -s tests -v
```

No remote targets are used by these tests.

## Data privacy and threat model

- Authorization and cookie **values** stay in the Burp process; MCP serves only role names, cookie names and bounded redacted metadata, including per-run HMAC value fingerprints. **Cookie names and JSON field names can still be sensitive**; inspect your client privacy policy.
- Raw baseline requests are retained only in Pun Java memory and visible in Pun's local inspector. Raw responses are not retained by Pun; use normal Burp history if needed.
- MCP receives URL **path without query**, HTTP method/status, **parameter/key names**, response byte count, and SHA-256 digest. The body itself is not exported.
- An untrusted website may supply misleading paths, parameter names, or JSON field names: treat model analysis as *untrusted input*, never follow instructions embedded in traffic.
- No cloud API is called by Pun code. Your **MCP client** may send observations to its model provider according to that client's own policy. Do not share out-of-scope or sensitive details.
- Test sessions are not stored on disk. Each Burp reload creates a new random bridge token. The port is fixed and must be free.
- Only exact hostnames saved in Pun **and** in Burp Target scope can be captured/replayed. No automatic scope expansion or workflow execution.

## Planned roadmap

- Burp Context Menu: "Send to Pun" on selected Proxy history items.
- Persist metadata opt-in with optional encrypted project storage (not cookies).
- Ownership lab: bind known object IDs to user-created test accounts.
- Stronger identity-aware diffing (safe response-field structure, test-owned sentinel values) without leaking PII.
- Explicit workflow transaction boundaries, snapshots/reset hooks and UI-guided step validation.
- Built-in local report viewer, optional redacted evidence export and safe rate limiting.

## Development notes

Java implementation: `burp-extension/src/main/java/dev/pun/PunExtension.java`.
Python implementation: `python/pun_mcp/`.

The extension should be tested in a disposable local lab and built with the official dependencies before use. This is an initial source MVP; runtime compatibility with an actual Burp installation has **not** yet been verified in the delivery environment.

License: MIT (applies to Pun original code only; Montoya API uses PortSwigger's license).

## Optional: disposable local test lab

A deliberately insecure **127.0.0.1-only** training server is included in `examples/local_lab.py` (stdlib only):

```powershell
python .\examples\local_lab.py
curl.exe -H "Cookie: session=userB" http://127.0.0.1:8888/api/orders/2002
```

The fake sessions are `session=userA` and `session=userB`. The lab intentionally contains both a cross-account read and a checkout state-transition flaw. Proxy requests through Burp, set its Target scope and Pun's allowlist to `127.0.0.1`, then test Pun with this lab before a real target. The data are made up and reset on restart.

**Important:** Burp's scope must include `http://127.0.0.1:8888/` explicitly if it is not already in scope. Configure Pun allowlist with `127.0.0.1` rather than `localhost` for this lab.

## Cookie Inspector & deep analysis (0.2)

**Burp UI:** Select a captured request in Pun → **Decode cookies locally**. Pun can inspect request `Cookie` and response `Set-Cookie` values, attempt bounded nested URL-percent, Base64/URL-safe Base64, hexadecimal, gzip-in-Base64, JSON, and JWT header/payload decoding. The **raw and decoded values stay in the Java UI**. No cryptographic JWT signature verification or JWT forgery is performed. Binary/encrypted formats cannot be decrypted without the proper key.

**Hashes:** Pun flags 32/40/64/128-character hexadecimal values as *MD5-like / SHA-1-like / SHA-256-like / SHA-512-like*. This is a length-and-character heuristic, NOT a verified algorithm, and these one-way hashes **cannot be decoded**. You can compare ONE plaintext candidate locally, with no network lookups or brute forcing:

```powershell
cd C:\Tools\Pun
.\.venv\Scripts\python.exe -m pun_mcp.cookie_cli inspect
.\.venv\Scripts\python.exe -m pun_mcp.cookie_cli verify
```

The `inspect` action prompts for a Cookie header or encoded value and shows the plaintext in the **local console**. The `verify` action prompts for a digest and a candidate. Input is hidden while typing. **Neither command invokes MCP or Burp**, and decoded content is never intentionally sent to an AI provider by Pun itself. For arbitrary plaintext containing `=`, use Burp's local decoder or prefix the CLI value with a cookie name (e.g. `test=...`).

**Advanced analysis** generates role-by-endpoint observations, prioritizes authorization hypotheses with bounded scores, and creates a coarse workflow transition graph. It does **not** infer server-side ownership, derive an exploit, prove a security bug, or automatically issue multi-step requests. Scores are research triage signals only. Unobserved events are not evidence that a prerequisite was skipped.

**MCP privacy design:** `list_observed_requests` now returns redacted structural cookie metadata (names, JSON key names, encoding types, small keyed HMAC aliases). It does not expose raw cookie or JWT claim values. The HMAC key is randomly generated each time Burp loads Pun. Labels may correlate traffic locally but do not establish identities. Scope restrictions and manual approval for replays remain unchanged.

**Current verification:** Python standard-library unit tests pass in the build environment, including new cookie and deep-analysis cases. The Java sources need a real Gradle build using Montoya/Gson dependencies and end-to-end testing inside a compatible Burp installation; static compilation checks against local API stubs do not substitute for that test.
