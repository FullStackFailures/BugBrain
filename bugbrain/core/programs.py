from pathlib import Path
import json

from .scope import normalize_host


PROGRAMS_FILE = Path("data/programs.json")


def _load():

    PROGRAMS_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    if not PROGRAMS_FILE.exists():

        PROGRAMS_FILE.write_text(
            "[]",
            encoding="utf-8"
        )

    try:

        return json.loads(
            PROGRAMS_FILE.read_text(
                encoding="utf-8"
            )
        )

    except json.JSONDecodeError:

        return []


def _save(programs):

    PROGRAMS_FILE.write_text(
        json.dumps(
            programs,
            indent=2
        ),
        encoding="utf-8"
    )


def add_program(
    name,
    platform="custom"
):

    programs = _load()

    for program in programs:

        if (
            program["name"].lower()
            == name.lower()
        ):

            return False

    programs.append({
        "name": name,
        "platform": platform,
        "targets": [],
        "rules": {
            "authorized": True
        }
    })

    _save(programs)

    return True


def list_programs():

    return _load()


def get_program(name):

    for program in _load():

        if (
            program["name"].lower()
            == name.lower()
        ):

            return program

    return None


def add_program_target(
    program_name,
    target
):

    programs = _load()

    target = normalize_host(
        target
    )

    for program in programs:

        if (
            program["name"].lower()
            == program_name.lower()
        ):

            if target not in program["targets"]:

                program["targets"].append(
                    target
                )

                _save(programs)

            return True

    return False


def target_in_program(
    program_name,
    target
):

    program = get_program(
        program_name
    )

    if not program:
        return False

    target = normalize_host(
        target
    )

    for allowed in program.get(
        "targets",
        []
    ):

        allowed = normalize_host(
            allowed
        )

        # Exact hostname/IP match.
        if target == allowed:
            return True

        # Wildcard scope, for example:
        # *.example.com
        if allowed.startswith("*."):

            base = allowed[2:]

            # The base domain itself is not automatically
            # included by wildcard scope.
            if target.endswith(
                "." + base
            ):
                return True

    return False
