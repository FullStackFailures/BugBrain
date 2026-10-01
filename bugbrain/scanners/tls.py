import socket
import ssl
from datetime import datetime, timezone


class TLSScanner:

    def scan(self, host, port=443):
        result = {
            "ok": False,
            "host": host,
            "port": port,
            "protocol": "",
            "cipher": "",
            "certificate": {},
            "error": ""
        }

        context = ssl.create_default_context()

        try:
            with socket.create_connection(
                (host, port),
                timeout=10
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=host
                ) as tls:

                    certificate = tls.getpeercert()

                    result["ok"] = True
                    result["protocol"] = tls.version() or ""
                    result["cipher"] = tls.cipher()[0] if tls.cipher() else ""

                    result["certificate"] = {
                        "subject": certificate.get("subject", ()),
                        "issuer": certificate.get("issuer", ()),
                        "serial_number": certificate.get("serialNumber", ""),
                        "not_before": certificate.get("notBefore", ""),
                        "not_after": certificate.get("notAfter", ""),
                        "san": certificate.get("subjectAltName", ())
                    }

                    return result

        except (OSError, ssl.SSLError) as exc:
            result["error"] = str(exc)
            return result