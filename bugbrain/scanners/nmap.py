import subprocess
import shutil
import xml.etree.ElementTree as ET


class NmapScanner:

    def scan(self, host):

        nmap = shutil.which("nmap")

        if not nmap:
            return {
                "ok": False,
                "error": "nmap is not installed",
                "ports": [],
                "stdout": "",
                "stderr": ""
            }

        command = [
            nmap,
            "-Pn",
            "--top-ports",
            "100",
            "-T3",
            "-oX",
            "-",
            host
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=180
            )

            ports = []

            root = ET.fromstring(result.stdout)

            for port in root.findall(
                ".//port"
            ):

                state = port.find("state")

                if state is None:
                    continue

                if state.get("state") != "open":
                    continue

                service = port.find("service")

                service_name = ""

                if service is not None:
                    service_name = service.get(
                        "name",
                        ""
                    )

                ports.append({
                    "port": int(
                        port.get("portid")
                    ),
                    "protocol": port.get(
                        "protocol",
                        "tcp"
                    ),
                    "service": service_name
                })

            return {
                "ok": result.returncode == 0,
                "ports": ports,
                "stdout": result.stdout,
                "stderr": result.stderr
            }

        except subprocess.TimeoutExpired:

            return {
                "ok": False,
                "error": "Nmap timed out",
                "ports": [],
                "stdout": "",
                "stderr": ""
            }

        except (
            ET.ParseError,
            OSError,
            ValueError
        ) as exc:

            return {
                "ok": False,
                "error": str(exc),
                "ports": [],
                "stdout": "",
                "stderr": ""
            }
