import re
from urllib.parse import urljoin, urlparse

import requests


# ============================================================
# GENERAL URL EXTRACTION
# ============================================================

ABSOLUTE_URL_PATTERN = re.compile(
    r"""["']((?:https?://)[^"'<>\\\s]{2,1000})["']""",
    re.IGNORECASE,
)

RELATIVE_URL_PATTERN = re.compile(
    r"""["']((?:/|\./|\.\./)[A-Za-z0-9_./?&=%:#@+\-~]{2,1000})["']"""
)

PATH_PATTERN = re.compile(
    r"""["']((?:/api/|/rest/|/graphql|/v[0-9]+/)[^"'<>\\\s]{0,500})["']""",
    re.IGNORECASE,
)


# ============================================================
# REQUEST PATTERNS
# ============================================================

FETCH_PATTERN = re.compile(
    r"""fetch\s*\(\s*["']([^"']{1,1000})["']""",
    re.IGNORECASE,
)

AXIOS_PATTERN = re.compile(
    r"""axios\.(?:get|post|put|patch|delete|head|options|request)
    \s*\(\s*["']([^"']{1,1000})["']""",
    re.IGNORECASE | re.VERBOSE,
)

XHR_PATTERN = re.compile(
    r"""\.open\s*\(
    \s*["'][A-Z]{3,10}["']
    \s*,\s*["']([^"']{1,1000})["']""",
    re.IGNORECASE | re.VERBOSE,
)

REQUEST_METHOD_PATTERN = re.compile(
    r"""(?:url|endpoint|baseURL|baseUrl|apiUrl|apiURL)
    \s*[:=]\s*["']([^"']{1,1000})["']""",
    re.IGNORECASE | re.VERBOSE,
)


# ============================================================
# WEBSOCKETS
# ============================================================

WEBSOCKET_PATTERN = re.compile(
    r"""["']((?:wss?|ws)://[^"'<>\\\s]{2,1000})["']""",
    re.IGNORECASE,
)


# ============================================================
# PARAMETERS
# ============================================================

PARAMETER_PATTERN = re.compile(
    r"""[?&]([A-Za-z_][A-Za-z0-9_-]{0,80})="""
)

OBJECT_PARAMETER_PATTERN = re.compile(
    r"""["']([A-Za-z_][A-Za-z0-9_-]{1,80})["']\s*:"""
)


# ============================================================
# SECURITY-SENSITIVE REFERENCES
# ============================================================

INTERESTING_PATTERN = re.compile(
    r"""["']([^"']{1,500}
    (?:login|logout|signin|signup|register|
    auth|oauth|oidc|token|session|password|reset|
    admin|administrator|dashboard|manage|
    account|profile|user|users|role|permission|
    upload|download|export|import|
    billing|payment|checkout|transaction|
    webhook|callback|graphql|swagger|openapi|
    debug|internal|private|health|metrics|
    actuator|console|socket|ws)
    [^"']{0,500})["']""",
    re.IGNORECASE | re.VERBOSE,
)


# ============================================================
# API DOCUMENTATION
# ============================================================

API_DOCUMENTATION_PATTERN = re.compile(
    r"""["']([^"']{1,500}
    (?:swagger|openapi|api-docs|
    redoc|rapidoc|graphql|graphiql|
    schema\.json|openapi\.json|swagger\.json|
    openapi\.yaml|openapi\.yml)
    [^"']{0,500})["']""",
    re.IGNORECASE | re.VERBOSE,
)


# ============================================================
# AUTH / OAUTH
# ============================================================

AUTH_PATTERN = re.compile(
    r"""["']([^"']{1,500}
    (?:oauth|oauth2|oidc|
    authorize|authorization|token|refresh_token|
    access_token|id_token|client_id|redirect_uri|
    jwks|\.well-known/openid-configuration)
    [^"']{0,500})["']""",
    re.IGNORECASE | re.VERBOSE,
)


# ============================================================
# CLIENT-SIDE ROUTES
# ============================================================

ROUTE_PATTERN = re.compile(
    r"""(?:router|route|navigate|navigateTo|push|replace)
    \s*\(\s*["']([^"']{1,500})["']""",
    re.IGNORECASE | re.VERBOSE,
)


# ============================================================
# SOURCE MAPS
# ============================================================

SOURCE_MAP_PATTERN = re.compile(
    r"""[#@]\s*sourceMappingURL=([^\s]+)"""
)


# ============================================================
# SERVICE WORKERS
# ============================================================

SERVICE_WORKER_PATTERN = re.compile(
    r"""navigator\.serviceWorker\.register
    \s*\(\s*["']([^"']+)["']""",
    re.IGNORECASE | re.VERBOSE,
)


# ============================================================
# TECHNOLOGY DETECTION
# ============================================================

TECHNOLOGY_PATTERNS = {
    "axios": re.compile(
        r"\baxios\b",
        re.IGNORECASE,
    ),

    "graphql": re.compile(
        r"\bgraphql\b",
        re.IGNORECASE,
    ),

    "apollo": re.compile(
        r"\bapollo\b",
        re.IGNORECASE,
    ),

    "react_query": re.compile(
        r"react[-_ ]query|@tanstack/query",
        re.IGNORECASE,
    ),

    "socket_io": re.compile(
        r"socket\.io",
        re.IGNORECASE,
    ),

    "jquery": re.compile(
        r"\bjQuery\b|\$\.(?:ajax|get|post)",
        re.IGNORECASE,
    ),

    "angular": re.compile(
        r"@angular|HttpClient",
        re.IGNORECASE,
    ),

    "vue": re.compile(
        r"\bvue\b|createApp",
        re.IGNORECASE,
    ),
}


class JavaScriptScanner:

    def __init__(
        self,
        timeout=10,
        user_agent="BugBrain/0.1",
    ):

        self.timeout = timeout

        self.session = requests.Session()

        self.session.headers.update({
            "User-Agent": user_agent
        })

    # ========================================================
    # URL NORMALIZATION
    # ========================================================

    @staticmethod
    def _normalise_url(
        value,
        base_url,
    ):

        value = value.strip()

        if not value:
            return None

        lowered = value.lower()

        if lowered.startswith(
            (
                "javascript:",
                "data:",
                "blob:",
                "#",
            )
        ):
            return None

        result = urljoin(
            base_url,
            value,
        )

        parsed = urlparse(result)

        if parsed.scheme not in (
            "http",
            "https",
        ):
            return None

        return result

    @staticmethod
    def _add_url(
        collection,
        value,
        base_url,
    ):

        normalised = JavaScriptScanner._normalise_url(
            value,
            base_url,
        )

        if normalised:
            collection.add(
                normalised
            )

    @staticmethod
    def _extract_parameters(
        javascript,
        parameters,
    ):

        for match in PARAMETER_PATTERN.findall(
            javascript
        ):

            parameters.add(
                match
            )

        for match in OBJECT_PARAMETER_PATTERN.findall(
            javascript
        ):

            if len(match) <= 80:

                parameters.add(
                    match
                )

    # ========================================================
    # MAIN SCANNER
    # ========================================================

    def scan(
        self,
        page_url,
    ):

        result = {
            "ok": False,
            "page_url": page_url,

            "scripts": [],
            "urls": [],
            "api_endpoints": [],
            "websocket_urls": [],
            "parameters": [],

            "interesting_references": [],
            "api_documentation": [],
            "auth_references": [],
            "routes": [],
            "service_workers": [],
            "source_maps": [],
            "technologies": [],

            "errors": [],
        }

        # ----------------------------------------------------
        # Fetch page
        # ----------------------------------------------------

        try:

            response = self.session.get(
                page_url,
                timeout=self.timeout,
                allow_redirects=True,
            )

            response.raise_for_status()

        except requests.RequestException as exc:

            result["errors"].append(
                str(exc)
            )

            return result

        html = response.text

        # ----------------------------------------------------
        # Script sources
        # ----------------------------------------------------

        script_sources = re.findall(
            r"""<script[^>]+src=["']([^"']+)["']""",
            html,
            re.IGNORECASE,
        )

        scripts = []

        for src in script_sources[:100]:

            script_url = self._normalise_url(
                src,
                response.url,
            )

            if not script_url:
                continue

            if script_url not in scripts:

                scripts.append(
                    script_url
                )

        result["scripts"] = scripts

        # ----------------------------------------------------
        # Discovery collections
        # ----------------------------------------------------

        discovered_urls = set()
        discovered_apis = set()
        discovered_websockets = set()
        discovered_parameters = set()

        interesting = set()
        api_documentation = set()
        auth_references = set()
        routes = set()
        service_workers = set()
        source_maps = set()
        technologies = set()

        # ----------------------------------------------------
        # Inline JavaScript
        # ----------------------------------------------------

        inline_scripts = re.findall(
            r"""<script(?:[^>]*)>(.*?)</script>""",
            html,
            re.IGNORECASE | re.DOTALL,
        )

        script_items = []

        # ----------------------------------------------------
        # External JavaScript
        # ----------------------------------------------------

        for script_url in scripts:

            try:

                script_response = self.session.get(
                    script_url,
                    timeout=self.timeout,
                    allow_redirects=True,
                )

                if not script_response.ok:
                    continue

                javascript = script_response.text[:500000]

                script_items.append(
                    (
                        script_url,
                        javascript,
                    )
                )

            except requests.RequestException as exc:

                result["errors"].append(
                    f"{script_url}: {exc}"
                )

        # ----------------------------------------------------
        # Inline JavaScript
        # ----------------------------------------------------

        for javascript in inline_scripts[:50]:

            script_items.append(
                (
                    response.url,
                    javascript[:500000],
                )
            )

        # ====================================================
        # ANALYZE JAVASCRIPT
        # ====================================================

        for script_url, javascript in script_items:

            # ------------------------------------------------
            # Absolute URLs
            # ------------------------------------------------

            for match in ABSOLUTE_URL_PATTERN.findall(
                javascript
            ):

                self._add_url(
                    discovered_urls,
                    match,
                    script_url,
                )

            # ------------------------------------------------
            # Relative URLs
            # ------------------------------------------------

            for match in RELATIVE_URL_PATTERN.findall(
                javascript
            ):

                self._add_url(
                    discovered_urls,
                    match,
                    script_url,
                )

            # ------------------------------------------------
            # API paths
            # ------------------------------------------------

            for match in PATH_PATTERN.findall(
                javascript
            ):

                endpoint = self._normalise_url(
                    match,
                    script_url,
                )

                if endpoint:

                    discovered_apis.add(
                        endpoint
                    )

                    discovered_urls.add(
                        endpoint
                    )

            # ------------------------------------------------
            # fetch()
            # ------------------------------------------------

            for match in FETCH_PATTERN.findall(
                javascript
            ):

                endpoint = self._normalise_url(
                    match,
                    script_url,
                )

                if endpoint:

                    discovered_urls.add(
                        endpoint
                    )

                    path = urlparse(
                        endpoint
                    ).path.lower()

                    if (
                        "/api/" in path
                        or "/graphql" in path
                        or re.search(
                            r"/v[0-9]+/",
                            path,
                            re.IGNORECASE,
                        )
                    ):

                        discovered_apis.add(
                            endpoint
                        )

            # ------------------------------------------------
            # Axios
            # ------------------------------------------------

            for match in AXIOS_PATTERN.findall(
                javascript
            ):

                endpoint = self._normalise_url(
                    match,
                    script_url,
                )

                if endpoint:

                    discovered_urls.add(
                        endpoint
                    )

                    discovered_apis.add(
                        endpoint
                    )

            # ------------------------------------------------
            # XMLHttpRequest
            # ------------------------------------------------

            for match in XHR_PATTERN.findall(
                javascript
            ):

                endpoint = self._normalise_url(
                    match,
                    script_url,
                )

                if endpoint:

                    discovered_urls.add(
                        endpoint
                    )

                    discovered_apis.add(
                        endpoint
                    )

            # ------------------------------------------------
            # URL variables
            # ------------------------------------------------

            for match in REQUEST_METHOD_PATTERN.findall(
                javascript
            ):

                endpoint = self._normalise_url(
                    match,
                    script_url,
                )

                if endpoint:

                    discovered_urls.add(
                        endpoint
                    )

            # ------------------------------------------------
            # WebSockets
            # ------------------------------------------------

            for match in WEBSOCKET_PATTERN.findall(
                javascript
            ):

                discovered_websockets.add(
                    match
                )

            # ------------------------------------------------
            # Parameters
            # ------------------------------------------------

            self._extract_parameters(
                javascript,
                discovered_parameters,
            )

            # ------------------------------------------------
            # Interesting security references
            # ------------------------------------------------

            for match in INTERESTING_PATTERN.findall(
                javascript
            ):

                interesting.add(
                    match
                )

            # ------------------------------------------------
            # API documentation
            # ------------------------------------------------

            for match in API_DOCUMENTATION_PATTERN.findall(
                javascript
            ):

                reference = self._normalise_url(
                    match,
                    script_url,
                )

                if reference:

                    api_documentation.add(
                        reference
                    )

                    discovered_urls.add(
                        reference
                    )

            # ------------------------------------------------
            # Authentication / OAuth
            # ------------------------------------------------

            for match in AUTH_PATTERN.findall(
                javascript
            ):

                reference = self._normalise_url(
                    match,
                    script_url,
                )

                if reference:

                    auth_references.add(
                        reference
                    )

                    discovered_urls.add(
                        reference
                    )

            # ------------------------------------------------
            # Client-side routes
            # ------------------------------------------------

            for match in ROUTE_PATTERN.findall(
                javascript
            ):

                if match.startswith(
                    (
                        "/",
                        "./",
                        "../",
                    )
                ):

                    route = self._normalise_url(
                        match,
                        script_url,
                    )

                    if route:

                        routes.add(
                            route
                        )

                        discovered_urls.add(
                            route
                        )

            # ------------------------------------------------
            # Service workers
            # ------------------------------------------------

            for match in SERVICE_WORKER_PATTERN.findall(
                javascript
            ):

                worker = self._normalise_url(
                    match,
                    script_url,
                )

                if worker:

                    service_workers.add(
                        worker
                    )

                    discovered_urls.add(
                        worker
                    )

            # ------------------------------------------------
            # Source maps
            # ------------------------------------------------

            for match in SOURCE_MAP_PATTERN.findall(
                javascript
            ):

                source_map = self._normalise_url(
                    match,
                    script_url,
                )

                if source_map:

                    source_maps.add(
                        source_map
                    )

            # ------------------------------------------------
            # Technology detection
            # ------------------------------------------------

            for name, pattern in TECHNOLOGY_PATTERNS.items():

                if pattern.search(
                    javascript
                ):

                    technologies.add(
                        name
                    )

        # ====================================================
        # HTML-LEVEL REFERENCES
        # ====================================================

        for match in API_DOCUMENTATION_PATTERN.findall(
            html
        ):

            reference = self._normalise_url(
                match,
                response.url,
            )

            if reference:

                api_documentation.add(
                    reference
                )

                discovered_urls.add(
                    reference
                )

        for match in SERVICE_WORKER_PATTERN.findall(
            html
        ):

            worker = self._normalise_url(
                match,
                response.url,
            )

            if worker:

                service_workers.add(
                    worker
                )

                discovered_urls.add(
                    worker
                )

        # ====================================================
        # FINAL RESULT
        # ====================================================

        result["urls"] = sorted(
            discovered_urls
        )[:1000]

        result["api_endpoints"] = sorted(
            discovered_apis
        )[:1000]

        result["websocket_urls"] = sorted(
            discovered_websockets
        )[:300]

        result["parameters"] = sorted(
            discovered_parameters
        )[:1000]

        result["interesting_references"] = sorted(
            interesting
        )[:1000]

        result["api_documentation"] = sorted(
            api_documentation
        )[:300]

        result["auth_references"] = sorted(
            auth_references
        )[:300]

        result["routes"] = sorted(
            routes
        )[:500]

        result["service_workers"] = sorted(
            service_workers
        )[:100]

        result["source_maps"] = sorted(
            source_maps
        )[:200]

        result["technologies"] = sorted(
            technologies
        )

        result["ok"] = True

        return result
