from collections import deque
from urllib.parse import (
    urljoin,
    urlparse,
    urldefrag,
    parse_qsl
)

import re
import requests
from bs4 import BeautifulSoup


class HTTPScanner:
    """
    Passive HTTP application discovery.

    This scanner discovers:
        - HTML pages
        - links
        - forms
        - form inputs
        - URL parameters
        - scripts
        - script source URLs
        - API-looking URLs
        - JSON endpoints
        - technology indicators
        - cookies
        - security-relevant response headers

    It does NOT attempt exploitation.
    """

    API_PATTERNS = (
        "/api/",
        "/api",
        "/graphql",
        "/rest/",
        "/v1/",
        "/v2/",
        "/v3/",
        "/swagger",
        "/openapi",
    )

    COMMON_DISCOVERY_PATHS = (
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
    )

    PARAMETER_NAMES = (
        "id",
        "uid",
        "user",
        "user_id",
        "userid",
        "account",
        "account_id",
        "file",
        "filename",
        "path",
        "url",
        "uri",
        "redirect",
        "redirect_uri",
        "return",
        "return_url",
        "next",
        "continue",
        "callback",
        "query",
        "search",
        "q",
        "cmd",
        "command",
        "exec",
        "template",
        "page",
        "view",
        "lang",
        "sort",
        "order",
        "filter",
    )

    def __init__(self, timeout=10, user_agent="BugBrain/0.2"):
        self.timeout = timeout

        self.session = requests.Session()

        self.session.headers.update({
            "User-Agent": user_agent
        })

    def scan(self, host, ports=None, max_pages=100):
        if ports is None:
            ports = [
                443,
                80,
                8000,
                8080,
                8443
            ]

        results = []

        for port in ports:

            if port in (80, 8000, 8080):
                schemes = ["http"]

            elif port in (443, 8443):
                schemes = ["https"]

            else:
                schemes = [
                    "https",
                    "http"
                ]

            for scheme in schemes:

                start_url = (
                    f"{scheme}://{host}:{port}"
                )

                result = self._crawl(
                    start_url,
                    max_pages=max_pages
                )

                if result:
                    results.extend(result)
                    break

        return results

    def _crawl(self, start_url, max_pages=100):

        queue = deque()

        queue.append(start_url)

        queued = {
            self._canonical(start_url)
        }

        visited = set()

        results = []

        parsed_start = urlparse(start_url)

        allowed_scheme = parsed_start.scheme
        allowed_host = parsed_start.hostname
        allowed_port = parsed_start.port

        # -----------------------------------------------------
        # Seed common discovery files
        # -----------------------------------------------------

        for path in self.COMMON_DISCOVERY_PATHS:

            discovery_url = urljoin(
                start_url,
                path
            )

            canonical = self._canonical(
                discovery_url
            )

            if canonical not in queued:
                queued.add(canonical)
                queue.append(discovery_url)

        while queue and len(visited) < max_pages:

            url = queue.popleft()

            canonical = self._canonical(url)

            if canonical in visited:
                continue

            visited.add(canonical)

            try:

                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True
                )

            except requests.RequestException:

                continue

            final = urlparse(
                response.url
            )

            # -------------------------------------------------
            # Stay on original origin
            # -------------------------------------------------

            if (
                final.scheme != allowed_scheme
                or final.hostname != allowed_host
                or final.port != allowed_port
            ):
                continue

            result = self.analyze_response(
                response
            )

            results.append(result)

            # -------------------------------------------------
            # Discover links / scripts / API endpoints
            # -------------------------------------------------

            discovered_urls = set()

            discovered_urls.update(
                result.get(
                    "links",
                    []
                )
            )

            discovered_urls.update(
                result.get(
                    "scripts",
                    []
                )
            )

            discovered_urls.update(
                result.get(
                    "api_endpoints",
                    []
                )
            )

            for discovered in discovered_urls:

                parsed = urlparse(
                    discovered
                )

                if parsed.scheme not in (
                    "http",
                    "https"
                ):
                    continue

                if parsed.hostname != allowed_host:
                    continue

                if parsed.scheme != allowed_scheme:
                    continue

                if parsed.port != allowed_port:
                    continue

                normalized = self._canonical(
                    discovered
                )

                if (
                    normalized not in visited
                    and normalized not in queued
                ):

                    queued.add(normalized)

                    queue.append(
                        discovered
                    )

        return results

    @staticmethod
    def _canonical(url):

        url, _ = urldefrag(url)

        return url.rstrip("/") or url

    def analyze_response(self, response):

        content_type = response.headers.get(
            "Content-Type",
            ""
        )

        result = {

            "url": response.url,

            "status": response.status_code,

            "headers": dict(
                response.headers
            ),

            "content_type": content_type,

            "content_length": len(
                response.content
            ),

            "body_preview": "",

            "title": "",

            "links": [],

            "forms": [],

            "scripts": [],

            "api_endpoints": [],

            "parameters": [],

            "cookies": [],

            "security_headers": {},

            "technologies": []

        }

        # -----------------------------------------------------
        # Security response headers
        # -----------------------------------------------------

        result["security_headers"] = (
            self.extract_security_headers(
                response
            )
        )

        # -----------------------------------------------------
        # Cookies
        # -----------------------------------------------------

        result["cookies"] = (
            self.extract_cookies(
                response
            )
        )

        # -----------------------------------------------------
        # HTML
        # -----------------------------------------------------

        if "text/html" in content_type.lower():

            result["body_preview"] = (
                response.text[:100000]
            )

            result.update(
                self.analyze_html(
                    response.text,
                    response.url
                )
            )

        # -----------------------------------------------------
        # Text / JSON / JavaScript
        # -----------------------------------------------------

        elif any(
            content_type.lower().startswith(
                prefix
            )
            for prefix in (
                "text/",
                "application/json",
                "application/javascript",
                "application/x-javascript",
            )
        ):

            body = response.text[:100000]

            result["body_preview"] = body

            result["api_endpoints"] = (
                self.extract_api_urls(
                    body,
                    response.url
                )
            )

        result["technologies"] = (
            self.detect_technologies(
                response
            )
        )

        result["parameters"] = (
            self.extract_url_parameters(
                response.url
            )
        )

        return result

    def analyze_html(
        self,
        html,
        base_url
    ):

        soup = BeautifulSoup(
            html,
            "html.parser"
        )

        title = ""

        if soup.title:

            title = soup.title.get_text(
                strip=True
            )

        links = []

        # -----------------------------------------------------
        # Links
        # -----------------------------------------------------

        for tag in soup.find_all(
            "a",
            href=True
        ):

            href = tag.get("href")

            if not href:
                continue

            absolute = urljoin(
                base_url,
                href
            )

            parsed = urlparse(
                absolute
            )

            if parsed.scheme not in (
                "http",
                "https"
            ):
                continue

            links.append(
                self._canonical(
                    absolute
                )
            )

            if len(links) >= 500:
                break

        # -----------------------------------------------------
        # Forms
        # -----------------------------------------------------

        forms = []

        for form in soup.find_all("form"):

            action = urljoin(
                base_url,
                form.get(
                    "action",
                    ""
                )
            )

            method = form.get(
                "method",
                "GET"
            ).upper()

            enctype = form.get(
                "enctype",
                ""
            )

            inputs = []

            for field in form.find_all(
                [
                    "input",
                    "textarea",
                    "select"
                ]
            ):

                field_name = (
                    field.get(
                        "name",
                        ""
                    ) or ""
                )

                field_type = (
                    field.get(
                        "type",
                        ""
                    ) or ""
                )

                inputs.append({

                    "name": field_name,

                    "type": field_type,

                    "value": field.get(
                        "value",
                        ""
                    ),

                    "required": (
                        field.has_attr(
                            "required"
                        )
                    )

                })

            forms.append({

                "action": action,

                "method": method,

                "enctype": enctype,

                "inputs": inputs

            })

            if len(forms) >= 100:
                break

        # -----------------------------------------------------
        # JavaScript
        # -----------------------------------------------------

        scripts = []

        for script in soup.find_all(
            "script"
        ):

            src = script.get("src")

            if src:

                absolute = urljoin(
                    base_url,
                    src
                )

                parsed = urlparse(
                    absolute
                )

                if parsed.scheme in (
                    "http",
                    "https"
                ):

                    scripts.append(
                        self._canonical(
                            absolute
                        )
                    )

            else:

                inline = script.get_text(
                    " ",
                    strip=True
                )

                scripts.extend(
                    self.extract_api_urls(
                        inline,
                        base_url
                    )
                )

        # -----------------------------------------------------
        # API endpoints
        # -----------------------------------------------------

        api_endpoints = (
            self.extract_api_urls(
                html,
                base_url
            )
        )

        return {

            "title": title,

            "links": sorted(
                set(links)
            ),

            "forms": forms,

            "scripts": sorted(
                set(scripts)
            ),

            "api_endpoints": sorted(
                set(api_endpoints)
            )

        }

    def extract_api_urls(
        self,
        text,
        base_url
    ):

        found = set()

        # Absolute URLs
        absolute_pattern = re.compile(
            r'https?://[^\s\'"<>]+',
            re.IGNORECASE
        )

        for match in absolute_pattern.findall(
            text
        ):

            cleaned = match.rstrip(
                ".,);]}"
            )

            parsed = urlparse(
                cleaned
            )

            if any(
                marker in parsed.path.lower()
                for marker in self.API_PATTERNS
            ):

                found.add(
                    self._canonical(
                        cleaned
                    )
                )

        # Relative API-looking paths
        relative_pattern = re.compile(
            r'["\']([^"\']*(?:/api/|/graphql|/rest/|/v[0-9]+/|/swagger|/openapi)[^"\']*)["\']',
            re.IGNORECASE
        )

        for match in relative_pattern.findall(
            text
        ):

            candidate = urljoin(
                base_url,
                match
            )

            parsed = urlparse(
                candidate
            )

            if parsed.scheme in (
                "http",
                "https"
            ):

                found.add(
                    self._canonical(
                        candidate
                    )
                )

        return sorted(found)

    def extract_url_parameters(
        self,
        url
    ):

        parsed = urlparse(url)

        parameters = []

        for name, value in parse_qsl(
            parsed.query,
            keep_blank_values=True
        ):

            name_lower = name.lower()

            category = (
                "interesting"
                if name_lower in self.PARAMETER_NAMES
                else "parameter"
            )

            parameters.append({

                "name": name,

                "value": value,

                "category": category

            })

        return parameters

    def extract_cookies(
        self,
        response
    ):

        cookies = []

        for cookie in response.cookies:

            rest = getattr(
                cookie,
                "_rest",
                {}
            )

            cookies.append({

                "name": cookie.name,

                "secure": bool(
                    cookie.secure
                ),

                "httponly": (
                    "HttpOnly" in rest
                    or "httponly" in rest
                ),

                "samesite": (
                    rest.get(
                        "SameSite"
                    )
                    or rest.get(
                        "samesite"
                    )
                )

            })

        return cookies

    def extract_security_headers(
        self,
        response
    ):

        headers = {
            key.lower(): value
            for key, value
            in response.headers.items()
        }

        interesting = (
            "content-security-policy",
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "cross-origin-opener-policy",
            "cross-origin-resource-policy",
            "cross-origin-embedder-policy",
        )

        return {
            name: headers.get(name)
            for name in interesting
            if name in headers
        }

    def detect_technologies(
        self,
        response
    ):

        technologies = []

        headers = {
            key.lower(): value
            for key, value
            in response.headers.items()
        }

        server = headers.get(
            "server"
        )

        if server:

            technologies.append(
                f"Server: {server}"
            )

        powered_by = headers.get(
            "x-powered-by"
        )

        if powered_by:

            technologies.append(
                f"X-Powered-By: {powered_by}"
            )

        cookies = headers.get(
            "set-cookie",
            ""
        )

        cookie_signatures = {

            "phpsessid": "PHP",

            "jsessionid": "Java",

            "asp.net": "ASP.NET",

            "laravel_session": "Laravel",

            "connect.sid": "Node.js / Express",

        }

        cookie_text = cookies.lower()

        for signature, technology in (
            cookie_signatures.items()
        ):

            if signature in cookie_text:

                technologies.append(
                    f"Cookie: {technology}"
                )

        # Framework indicators

        body = response.text[:50000].lower()

        if "webpack" in body:

            technologies.append(
                "Webpack"
            )

        if "react" in body:

            technologies.append(
                "React"
            )

        if "angular" in body:

            technologies.append(
                "Angular"
            )

        if "vue" in body:

            technologies.append(
                "Vue"
            )

        return sorted(
            set(technologies)
        )
