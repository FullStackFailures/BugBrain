import shutil
import subprocess

from .config import get_tools


class ToolRunner:

    @staticmethod
    def available(command):
        return shutil.which(command) is not None

    @staticmethod
    def installed_tools():

        tools = get_tools()
        result = []

        for tool in tools:

            command = tool.get("command")

            if not command:
                continue

            result.append({
                **tool,
                "installed": ToolRunner.available(
                    command
                )
            })

        return result

    @staticmethod
    def run(
        command,
        args=None,
        timeout=120
    ):

        args = args or []

        executable = shutil.which(command)

        if not executable:

            return {
                "ok": False,
                "error": f"{command} is not installed",
                "stdout": "",
                "stderr": ""
            }

        process = [
            executable,
            *args
        ]

        try:

            result = subprocess.run(
                process,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            return {
                "ok": result.returncode == 0,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }

        except subprocess.TimeoutExpired:

            return {
                "ok": False,
                "error": "Command timed out",
                "stdout": "",
                "stderr": ""
            }

        except OSError as exc:

            return {
                "ok": False,
                "error": str(exc),
                "stdout": "",
                "stderr": ""
            }