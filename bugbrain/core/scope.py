from urllib.parse import urlparse
import fnmatch

from .config import SCOPES_FILE, load_json, save_json


def normalize_host(value):
    value = value.strip()

    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or ""

    value = value.lower().strip()

    if value.endswith("."):
        value = value[:-1]

    return value


def add_scope(target):
    target = normalize_host(target)

    if not target:
        raise ValueError("Invalid target")

    scopes = load_json(
        SCOPES_FILE,
        []
    )

    if target not in scopes:
        scopes.append(target)

        save_json(
            SCOPES_FILE,
            scopes
        )

        return True

    return False


def remove_scope(target):
    target = normalize_host(target)

    scopes = load_json(
        SCOPES_FILE,
        []
    )

    if target in scopes:
        scopes.remove(target)

        save_json(
            SCOPES_FILE,
            scopes
        )

        return True

    return False


def list_scope():
    return load_json(
        SCOPES_FILE,
        []
    )


def is_in_scope(target):
    host = normalize_host(target)

    for pattern in list_scope():

        pattern = pattern.lower()

        if fnmatch.fnmatch(
            host,
            pattern
        ):
            return True

        if host == pattern:
            return True

        if pattern.startswith("*."):

            base = pattern[2:]

            if (
                host == base
                or host.endswith("." + base)
            ):
                return True

    return False