import socket


class DNSScanner:

    def scan(self, host):
        result = {
            "ok": False,
            "host": host,
            "addresses": [],
            "canonical_name": "",
            "error": ""
        }

        try:
            info = socket.getaddrinfo(
                host,
                None,
                type=socket.SOCK_STREAM
            )

            addresses = sorted({
                item[4][0]
                for item in info
                if item[4]
            })

            result["addresses"] = addresses

            try:
                result["canonical_name"] = socket.getfqdn(host)
            except OSError:
                pass

            result["ok"] = bool(addresses)

        except socket.gaierror as exc:
            result["error"] = str(exc)

        except OSError as exc:
            result["error"] = str(exc)

        return result
