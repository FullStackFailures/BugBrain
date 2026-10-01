# BugBrain

BugBrain is a modular security assessment and bug-bounty research assistant written in Python. The current implementation combines scope enforcement, network reconnaissance, HTTP/HTTPS discovery, DNS/TLS inspection, JavaScript/API discovery, passive web-security analysis, vulnerability-candidate correlation, evidence-based verification, and Markdown reporting.

The normal scan path is intentionally non-destructive. Potential vulnerabilities are treated as **candidates** until the verification/evidence pipeline can justify confirmation.

> **Authorization:** Use BugBrain only against systems and applications you are explicitly authorized to assess. Do not add third-party targets to scope unless the applicable program, owner, or written authorization permits your testing.

## Current project layout

```text
bugbrain/
├── bugbrain/
│   ├── __main__.py
│   ├── cli.py
│   ├── config/
│   │   ├── config.json
│   │   └── tools.json
│   ├── core/
│   │   ├── config.py
│   │   ├── programs.py
│   │   ├── recon_storage.py
│   │   ├── runner.py
│   │   ├── scope.py
│   │   └── storage.py
│   ├── engine/
│   │   ├── active_mode.py
│   │   ├── active_permission.py
│   │   ├── analyzer.py
│   │   ├── confidence.py
│   │   ├── evidence.py
│   │   ├── exploitability.py
│   │   ├── exploitability_evidence.py
│   │   ├── exploitability_sqli.py
│   │   ├── planner.py
│   │   ├── recon.py
│   │   ├── verification_audit.py
│   │   ├── verification_http.py
│   │   ├── verification_policy.py
│   │   ├── verifier.py
│   │   ├── verifier_registry.py
│   │   └── vulnerability.py
│   ├── modules/
│   │   ├── advanced_security.py
│   │   ├── auth_security.py
│   │   ├── endpoint_intelligence.py
│   │   ├── exposure.py
│   │   ├── finding_engine.py
│   │   ├── headers.py
│   │   ├── injection_indicators.py
│   │   ├── modern_security.py
│   │   ├── parameter_security.py
│   │   ├── passive_security.py
│   │   ├── tls_security.py
│   │   ├── vulnerability_signatures.py
│   │   └── web_security.py
│   ├── reports/
│   │   └── reporter.py
│   ├── scanners/
│   │   ├── dns.py
│   │   ├── http.py
│   │   ├── javascript.py
│   │   ├── nmap.py
│   │   └── tls.py
│   └── data/
│       ├── scopes.json
│       ├── findings.json
│       └── active_verification_audit.jsonl
├── active_test_app/
│   └── app.py
├── data/
│   └── programs.json
└── requirements.txt
```

The uploaded project snapshot also contains historical backups, previous workspaces, logs, and a bundled virtual environment. Those are development/runtime artifacts rather than installation requirements.

## Requirements

### Operating system

Linux is the primary environment for the current project. Kali Linux/Debian-based systems are a natural fit because BugBrain currently relies on Nmap for network reconnaissance.

### Software

* Python 3.10+ recommended
* `pip` and Python virtual-environment support
* Nmap
* Network access to the authorized target when performing remote assessments

### Python packages

The current `requirements.txt` contains:

```text
requests>=2.31
beautifulsoup4>=4.12
click>=8.1
rich>=13.7
dnspython>=2.6
```

## Installation

Clone the repository and enter the project root:

```bash
git clone https://github.com/FullStackFailures/BugBrain.git
cd bugbrain
```

Install the system dependency:

```bash
sudo apt update
sudo apt install -y nmap python3 python3-pip python3-venv
```

Create a clean virtual environment. **Do not rely on the `.venv` included in an archive or copied from another machine.** Virtual environments contain machine-specific paths and interpreters and are not portable.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Verify the environment:

```bash
python --version
nmap --version
python -m bugbrain --help
```

You should see the BugBrain command list, including `scan`, `scope-add`, `scope-list`, `findings`, `runs`, and the program-management commands.

## Important: run from the repository root

The current implementation is not installed as a conventional Python package: there is no `pyproject.toml` or `setup.py` in the project snapshot.

Run it from the directory that contains both the `bugbrain/` package directory and `requirements.txt`:

```bash
cd /path/to/bugbrain
source .venv/bin/activate
python -m bugbrain --help
```

This is important because scan history and program data use relative paths such as `workspaces/` and `data/programs.json`.

## Quick start

### 1. Add an authorized target to scope

BugBrain normally requires a target to be explicitly present in the local scope list before scanning it.

For a hostname:

```bash
python -m bugbrain scope-add example.com
```

For an IP address:

```bash
python -m bugbrain scope-add 192.0.2.10
```

For a URL, `scope-add` normalizes the hostname before storing it:

```bash
python -m bugbrain scope-add https://example.com
```

Review current scope:

```bash
python -m bugbrain scope-list
```

### 2. Run a normal scan

Use the hostname or IP address as the scan target:

```bash
python -m bugbrain scan example.com
```

Local example:

```bash
python -m bugbrain scan 127.0.0.1
```

For the current implementation, passing a bare hostname/IP is preferred over passing a full `https://...` URL because the network and HTTP scanners build their own protocol/port combinations.

### 3. Review stored findings

```bash
python -m bugbrain findings
```

### 4. List previous scan runs

```bash
python -m bugbrain runs
```

### 5. Inspect a previous run

The run directory has the form:

```text
workspaces/<target>/<YYYYMMDD-HHMMSS>/
```

Example:

```bash
python -m bugbrain run-show example.com 20261001-203000
```

Use the exact target directory and run directory printed by `runs`.

## Complete CLI reference

Show the global help:

```bash
python -m bugbrain --help
```

Current commands:

```text
findings
program-add
program-list
program-target-add
run-show
runs
scan
scope-add
scope-list
```

### Scope commands

Add an authorized target:

```bash
python -m bugbrain scope-add example.com
```

List authorized targets:

```bash
python -m bugbrain scope-list
```

### Program commands

Add a bug-bounty/security program:

```bash
python -m bugbrain program-add "Example Program" --platform custom
```

List programs:

```bash
python -m bugbrain program-list
```

Add an authorized target to a program:

```bash
python -m bugbrain program-target-add "Example Program" example.com
```

Scan using a program entry instead of the global scope list:

```bash
python -m bugbrain scan example.com --program "Example Program"
```

Program target matching supports exact hostnames/IPs and wildcard subdomains such as:

```text
*.example.com
```

### Findings

```bash
python -m bugbrain findings
```

### Scan history

```bash
python -m bugbrain runs
```

### Previous-run inspection

```bash
python -m bugbrain run-show <target> <run>
```

## Scan behavior

The planner reads `bugbrain/config/config.json` and selects enabled capabilities. When Nmap is installed and enabled, network reconnaissance is included.

A normal scan can perform the following stages:

1. **Network reconnaissance** using Nmap.
2. **HTTP/HTTPS discovery** against web services identified by Nmap/common web ports.
3. **DNS reconnaissance** using Python's resolver/socket facilities.
4. **JavaScript/API reconnaissance**, including script URLs, API-looking paths, routes, authentication-related references, WebSocket references, documentation references, parameters, and technology indicators.
5. **TLS inspection** for HTTPS services, including protocol, cipher, certificate metadata, SANs, and validity dates.
6. **Security-header analysis**.
7. **Exposure checks** for each discovered web origin.
8. **Web-security analysis**.
9. **Authentication and access-control candidate analysis**.
10. **Parameter/input analysis**.
11. **Injection/XSS/SSRF indicator analysis**.
12. **Passive security analysis**.
13. **Modern API/security analysis**.
14. **Endpoint intelligence analysis**.
15. **Extended vulnerability-signature analysis**.
16. **Finding normalization, confidence analysis, exploitability assessment, and evidence verification**.
17. **Confirmed-finding storage and Markdown reporting**.

The current Nmap scanner uses `-Pn`, `--top-ports 100`, and `-T3` and requests XML output for parsing.

## Candidate vs confirmed findings

BugBrain deliberately separates detection from confirmation.

A scanner or heuristic module can report an observation such as an SQL-injection candidate, XSS reflection candidate, SSRF candidate, IDOR candidate, sensitive endpoint, or API surface. That does **not** automatically make the finding confirmed.

The verification pipeline applies evidence and confidence rules. Anything that does not pass the final confirmation gate is stored/displayed as a **candidate requiring verification** rather than as a confirmed vulnerability.

This distinction is important when reviewing output for bug-bounty reporting or internal security assessments.

## Active Verification Mode

Normal scans do not require the active verification password.

The current project includes a separate password-protected active mode. It is intended for explicitly authorized environments where a limited verification action is appropriate.

### Configure the active-mode password

Set the password in the environment rather than storing it in source code:

```bash
export BUGBRAIN_ACTIVE_VERIFY_PASSWORD='choose-a-local-secret'
```

Then run:

```bash
python -m bugbrain scan example.com --active
```

BugBrain will prompt for the password. A correct password enables active verification for that process.

The active verification implementation also applies additional controls, including:

* the target must be in BugBrain scope;
* only HTTP/HTTPS verification URLs are accepted;
* only GET, HEAD, and POST are allowed by the verification policy;
* a response-size limit is enforced by the policy;
* the local operator must explicitly answer `YES` for a potentially impactful verification test;
* permission decisions are written to the local audit log;
* the active-mode password is not written to that audit log.

The source currently registers a built-in active verifier for the `sqli_candidate` finding type. Its implementation is described in the project as a benign differential check and is guarded by the active-mode and permission controls.

### Disable the active password after use

```bash
unset BUGBRAIN_ACTIVE_VERIFY_PASSWORD
```

## Configuration

Main configuration:

```text
bugbrain/config/config.json
```

Current defaults:

```json
{
  "settings": {
    "timeout": 10,
    "max_redirects": 5,
    "user_agent": "BugBrain/0.1",
    "safe_mode": true
  },
  "modules": {
    "http": true,
    "nmap": true,
    "headers": true,
    "exposure": true,
    "dns": true,
    "tls": true,
    "javascript": true,
    "vulnerability": true
  }
}
```

Tool configuration:

```text
bugbrain/config/tools.json
```

Current external tool definition:

```json
[
  {
    "name": "nmap",
    "command": "nmap",
    "enabled": true,
    "capabilities": [
      "port_scan",
      "service_detection"
    ]
  }
]
```

### Configuration notes

`timeout` controls HTTP-related request timeouts and exposure checks.

`user_agent` is sent by the HTTP and JavaScript scanners.

`safe_mode` is expected to remain `true`; the active verification policy requires it.

The planner explicitly uses the `dns`, `http`, `headers`, `exposure`, `tls`, `javascript`, and `nmap` module settings when constructing its task list. Some additional module configuration keys exist in the JSON but are not independently consulted by the current planner, so treat those as implementation details rather than assuming they disable every downstream analyzer.

## Output and storage

Each scan creates a workspace under:

```text
workspaces/<target>/<timestamp>/
```

Typical files include:

```text
nmap.json
http.json
dns.json
javascript.json
tls.json
recon.json
bugbrain-YYYYMMDD-HHMMSS.md
```

### What the files contain

`nmap.json` contains parsed open-port/service information plus command output fields.

`http.json` contains HTTP discovery records such as status, headers, content type, page metadata, links, forms, scripts, API-looking URLs, parameters, cookies, and technology indicators.

`dns.json` contains resolved addresses and the canonical-name result.

`javascript.json` contains JavaScript/API reconnaissance findings.

`tls.json` contains TLS protocol, cipher, and certificate metadata collected from HTTPS services.

`recon.json` contains the correlated application-level reconnaissance view.

`bugbrain-*.md` is the human-readable assessment report.

Stored confirmed findings are maintained in:

```text
bugbrain/data/findings.json
```

The global scope list is maintained in:

```text
bugbrain/data/scopes.json
```

Active verification audit decisions are written to:

```text
bugbrain/data/active_verification_audit.jsonl
```

Program definitions are maintained in:

```text
data/programs.json
```

## Recommended clean setup for a Git repository

The uploaded project snapshot contains generated/runtime material that generally should not be committed as part of a clean source release, especially:

```text
.venv/
workspaces/
bugbrain_scan.log
bugbrain/data/active_verification_audit.jsonl
bugbrain/data/scopes.json
bugbrain/data/findings.json
__pycache__/
*.pyc
```

If this repository is going to be published or shared, review generated data first and remove any live targets, private test information, audit history, or other environment-specific artifacts.

A typical `.gitignore` can include:

```gitignore
.venv/
__pycache__/
*.py[cod]
workspaces/
bugbrain_scan.log
bugbrain/data/active_verification_audit.jsonl
```

Whether `scopes.json`, `findings.json`, and `data/programs.json` are ignored or versioned is a project-management decision; do not commit real target scope merely because the file exists in the repository.

## Local test application

The repository includes a small controlled test server for local development:

```text
active_test_app/app.py
```

Start it in one terminal:

```bash
python active_test_app/app.py
```

It listens on:

```text
http://127.0.0.1:8000
```

In another terminal, activate the same virtual environment and add localhost to scope:

```bash
source .venv/bin/activate
python -m bugbrain scope-add 127.0.0.1
python -m bugbrain scan 127.0.0.1
```

The local test application exposes `/` and `/item?id=...` so the scanner has a controlled page and parameter surface to discover.

Stop the test application with `Ctrl+C` when finished.

## Example workflow for an authorized assessment

```bash
# 1. Enter the project
cd /path/to/bugbrain

# 2. Activate the environment
source .venv/bin/activate

# 3. Confirm dependencies
python --version
nmap --version
python -m bugbrain --help

# 4. Register only the authorized host
python -m bugbrain scope-add example.com

# 5. Confirm scope
python -m bugbrain scope-list

# 6. Run the normal assessment
python -m bugbrain scan example.com

# 7. Review confirmed findings stored by the application
python -m bugbrain findings

# 8. Review scan history
python -m bugbrain runs
```

To use program-scoped authorization instead:

```bash
python -m bugbrain program-add "Example Security Program" --platform custom
python -m bugbrain program-target-add "Example Security Program" example.com
python -m bugbrain scan example.com --program "Example Security Program"
```

## Troubleshooting

### `ModuleNotFoundError: No module named ...`

Make sure the virtual environment is active and install the requirements again:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### `nmap is not installed`

Install Nmap:

```bash
sudo apt update
sudo apt install -y nmap
```

Then verify:

```bash
nmap --version
```

Nmap is particularly important in the current implementation because the HTTP scanner is normally given web ports discovered by the Nmap stage.

### `Target is not in scope`

Add the target first:

```bash
python -m bugbrain scope-add example.com
```

Then verify:

```bash
python -m bugbrain scope-list
```

Or configure the target under a program and use `--program`.

### Scan completes with no HTTP results

Check these items:

```bash
nmap --version
python -m bugbrain scope-list
```

Then inspect the scan workspace:

```bash
python -m bugbrain runs
```

The current workflow relies on Nmap to identify web ports before HTTP discovery. A target that does not expose a discovered/common web service may therefore produce no HTTP results.

### TLS errors

TLS inspection uses Python's standard SSL context. Targets with certificate, protocol, SNI, or trust-chain issues may fail TLS inspection even when the service itself is reachable. Review `tls.json` in the scan workspace for the recorded error.

### The extracted `.venv` fails to start

Do not use the bundled environment from an archive. Recreate it on the current machine:

```bash
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### `python -m bugbrain` works, but data appears in an unexpected directory

Run BugBrain from the repository root. Some state paths are deliberately relative to the current working directory, including scan workspaces and the program database.

## Development

The codebase is organized into four main layers:

* `scanners/` — low-level collection of network, HTTP, DNS, TLS, and JavaScript observations.
* `modules/` — security-analysis modules that convert observations into findings/candidates.
* `engine/` — planning, correlation, confidence, exploitability, evidence, and verification logic.
* `reports/` — human-readable Markdown reporting.

The command-line interface is implemented in:

```text
bugbrain/cli.py
```

The executable module entry point is:

```text
bugbrain/__main__.py
```

When developing a new scanner or analyzer, keep the distinction between **observation**, **candidate**, and **confirmed finding** intact. A heuristic match should not be promoted directly to confirmed vulnerability status.

## Architecture at a glance

```text
Target
  │
  ├── Scope / Program authorization
  │
  ▼
Planner
  │
  ├── Nmap
  ├── HTTP/HTTPS
  ├── DNS
  ├── TLS
  └── JavaScript/API
  │
  ▼
Recon correlation
  │
  ▼
Security analysis modules
  │
  ├── headers / exposure / web security
  ├── auth / access control
  ├── parameter / injection indicators
  ├── passive / modern security
  └── endpoint intelligence / signatures
  │
  ▼
Analyzer + confidence + exploitability
  │
  ▼
Evidence verification
  │
  ├── confirmed
  └── candidate / verification required
  │
  ▼
Storage + Markdown report
```

## Security and operational considerations

BugBrain is an assessment tool, not a substitute for authorization, manual validation, or program-specific testing rules.

Before a remote scan, confirm:

* the hostname/IP is explicitly in scope;
* the testing window and rate limits permit automated scanning;
* the requested endpoints and parameters are permitted;
* any active verification is separately authorized where required;
* generated reports and audit logs are stored securely.

For production use, treat `workspaces/`, findings data, and audit logs as potentially sensitive assessment artifacts.

## License

BugBrain is licensed under the MIT License.

See the [LICENSE](LICENSE) file for the full license text.

## Status

This README documents the behavior of the supplied project snapshot. The codebase is an actively developed foundation and contains historical backup directories and generated scan artifacts. Treat the current CLI and source tree as authoritative when extending the project.
