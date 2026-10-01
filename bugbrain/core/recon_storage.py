import json
from pathlib import Path
from datetime import datetime


def safe_name(value):
    return (
        value
        .replace("/", "_")
        .replace(":", "_")
        .replace("\\", "_")
        .replace("?", "_")
        .replace("&", "_")
    )


def create_workspace(target):

    target_dir = safe_name(target)

    timestamp = datetime.now().strftime(
        "%Y%m%d-%H%M%S"
    )

    directory = (
        Path("workspaces")
        / target_dir
        / timestamp
    )

    directory.mkdir(
        parents=True,
        exist_ok=True
    )

    return directory


def save_json(
    workspace,
    filename,
    data
):

    path = (
        Path(workspace)
        / filename
    )

    path.write_text(
        json.dumps(
            data,
            indent=2,
            default=str
        ),
        encoding="utf-8"
    )

    return path


def save_recon(
    target,
    recon,
    workspace=None
):

    if workspace is None:
        workspace = create_workspace(
            target
        )

    return save_json(
        workspace,
        "recon.json",
        recon
    )


def save_http_results(
    workspace,
    results
):

    return save_json(
        workspace,
        "http.json",
        results
    )


def save_nmap_result(
    workspace,
    result
):

    return save_json(
        workspace,
        "nmap.json",
        result
    )
