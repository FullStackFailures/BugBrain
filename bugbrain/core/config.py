from pathlib import Path
import json


ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = ROOT / "data"
WORKSPACE_DIR = ROOT / "workspaces"
CONFIG_DIR = ROOT / "config"

SCOPES_FILE = DATA_DIR / "scopes.json"
FINDINGS_FILE = DATA_DIR / "findings.json"
CONFIG_FILE = CONFIG_DIR / "config.json"
TOOLS_FILE = CONFIG_DIR / "tools.json"


DEFAULT_CONFIG = {
    "settings": {
        "timeout": 10,
        "max_redirects": 5,
        "user_agent": "BugBrain/0.1",
        "safe_mode": True
    },

    "modules": {
        "http": True,
        "nmap": True,
        "headers": True,
        "exposure": True
    }
}


DEFAULT_TOOLS = [
    {
        "name": "nmap",
        "command": "nmap",
        "enabled": True,
        "capabilities": [
            "port_scan",
            "service_detection"
        ]
    }
]


def ensure_directories():
    DATA_DIR.mkdir(exist_ok=True)
    WORKSPACE_DIR.mkdir(exist_ok=True)
    CONFIG_DIR.mkdir(exist_ok=True)


def load_json(path, default):
    ensure_directories()

    if not path.exists():
        save_json(path, default)
        return default

    try:
        return json.loads(
            path.read_text(encoding="utf-8")
        )
    except (json.JSONDecodeError, OSError):
        return default


def save_json(path, data):
    ensure_directories()

    path.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8"
    )


def get_config():
    return load_json(
        CONFIG_FILE,
        DEFAULT_CONFIG
    )


def get_tools():
    return load_json(
        TOOLS_FILE,
        DEFAULT_TOOLS
    )