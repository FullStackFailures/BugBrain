from urllib.parse import urlparse, parse_qsl


class ReconEngine:
    def __init__(
        self,
        target,
        http_results,
        javascript_results=None
    ):
        self.target = target
        self.http_results = http_results
        self.javascript_results = javascript_results or []

    @staticmethod
    def _add_value(collection, value):
        if value:
            collection.add(str(value))

    @staticmethod
    def _add_asset(assets, asset_type, **data):
        asset = {"type": asset_type}
        asset.update(data)
        assets.append(asset)

    def build(self):
        assets = []

        urls = set()
        hosts = set()
        technologies = set()

        forms = []

        javascript_urls = set()
        api_endpoints = set()
        websocket_urls = set()
        parameters = set()
        source_maps = set()

        api_documentation = set()
        auth_references = set()
        routes = set()
        service_workers = set()

        cookies = []
        security_headers = []

        # -----------------------------------------------------
        # HTTP reconnaissance
        # -----------------------------------------------------

        for result in self.http_results:

            if result.get("error"):
                continue

            base_url = result.get("url", "")

            if base_url:
                urls.add(base_url)

            # -------------------------------------------------
            # Discovered links
            # -------------------------------------------------

            for link in result.get("links", []):
                if link:
                    urls.add(link)

            # -------------------------------------------------
            # Scripts discovered by HTTP scanner
            # -------------------------------------------------

            for script in result.get("scripts", []):
                if script:
                    javascript_urls.add(script)
                    urls.add(script)

            # -------------------------------------------------
            # API endpoints discovered by HTTP scanner
            # -------------------------------------------------

            for endpoint in result.get("api_endpoints", []):
                if endpoint:
                    api_endpoints.add(endpoint)
                    urls.add(endpoint)

            # -------------------------------------------------
            # Technologies
            # -------------------------------------------------

            for technology in result.get("technologies", []):
                if technology:
                    technologies.add(str(technology))

            # -------------------------------------------------
            # Forms
            # -------------------------------------------------

            for form in result.get("forms", []):
                forms.append(form)

                action = form.get("action", "")

                if action:
                    urls.add(action)

                for field in form.get("inputs", []):
                    name = field.get("name", "")

                    if name:
                        parameters.add(name)

            # -------------------------------------------------
            # URL parameters
            # -------------------------------------------------

            for parameter in result.get("parameters", []):

                if isinstance(parameter, dict):
                    name = parameter.get("name", "")

                    if name:
                        parameters.add(name)

                elif parameter:
                    parameters.add(str(parameter))

            # -------------------------------------------------
            # Cookies
            # -------------------------------------------------

            for cookie in result.get("cookies", []):
                if cookie:
                    cookies.append(cookie)

            # -------------------------------------------------
            # Security headers
            # -------------------------------------------------

            headers = result.get("security_headers", {})

            if headers:
                security_headers.append({
                    "url": base_url,
                    "headers": headers
                })

            # -------------------------------------------------
            # Extract query parameters directly from URL
            # -------------------------------------------------

            if base_url:

                try:
                    parsed = urlparse(base_url)

                    for name, value in parse_qsl(
                        parsed.query,
                        keep_blank_values=True
                    ):
                        if name:
                            parameters.add(name)

                except Exception:
                    pass

        # -----------------------------------------------------
        # JavaScript reconnaissance
        # -----------------------------------------------------

        for result in self.javascript_results:

            # -------------------------------------------------
            # URLs discovered in JavaScript
            # -------------------------------------------------

            for url in result.get("urls", []):
                if url:
                    urls.add(url)

            # -------------------------------------------------
            # JavaScript files
            # -------------------------------------------------

            for script in result.get("scripts", []):
                if script:
                    javascript_urls.add(script)
                    urls.add(script)

            # -------------------------------------------------
            # API endpoints
            # -------------------------------------------------

            for endpoint in result.get("api_endpoints", []):
                if endpoint:
                    api_endpoints.add(endpoint)
                    urls.add(endpoint)

            # -------------------------------------------------
            # WebSockets
            # -------------------------------------------------

            for websocket in result.get("websocket_urls", []):
                if websocket:
                    websocket_urls.add(websocket)

            # -------------------------------------------------
            # Parameters
            # -------------------------------------------------

            for parameter in result.get("parameters", []):
                if parameter:
                    parameters.add(str(parameter))

            # -------------------------------------------------
            # Source maps
            # -------------------------------------------------

            for source_map in result.get("source_maps", []):
                if source_map:
                    source_maps.add(source_map)
                    urls.add(source_map)

            # -------------------------------------------------
            # API documentation
            # -------------------------------------------------

            for documentation in result.get("api_documentation", []):
                if documentation:
                    api_documentation.add(documentation)
                    urls.add(documentation)

            # -------------------------------------------------
            # Authentication references
            # -------------------------------------------------

            for reference in result.get("auth_references", []):
                if reference:
                    auth_references.add(reference)
                    urls.add(reference)

            # -------------------------------------------------
            # Application routes
            # -------------------------------------------------

            for route in result.get("routes", []):
                if route:
                    routes.add(route)
                    urls.add(route)

            # -------------------------------------------------
            # Service workers
            # -------------------------------------------------

            for worker in result.get("service_workers", []):
                if worker:
                    service_workers.add(worker)
                    urls.add(worker)

            # -------------------------------------------------
            # JavaScript technologies
            # -------------------------------------------------

            for technology in result.get("technologies", []):
                if technology:
                    technologies.add(str(technology))

        # -----------------------------------------------------
        # Hosts
        # -----------------------------------------------------

        for url in urls:

            try:
                parsed = urlparse(url)

                if parsed.hostname:
                    hosts.add(parsed.hostname.lower())

            except Exception:
                continue

        for endpoint in api_endpoints:

            try:
                parsed = urlparse(endpoint)

                if parsed.hostname:
                    hosts.add(parsed.hostname.lower())

            except Exception:
                continue

        for websocket in websocket_urls:

            try:
                parsed = urlparse(websocket)

                if parsed.hostname:
                    hosts.add(parsed.hostname.lower())

            except Exception:
                continue

        # -----------------------------------------------------
        # Asset records
        # -----------------------------------------------------

        for host in sorted(hosts):
            self._add_asset(
                assets,
                "web_host",
                host=host
            )

        for url in sorted(urls):
            self._add_asset(
                assets,
                "url",
                url=url
            )

        for script in sorted(javascript_urls):
            self._add_asset(
                assets,
                "javascript",
                url=script
            )

        for endpoint in sorted(api_endpoints):
            self._add_asset(
                assets,
                "api_endpoint",
                url=endpoint
            )

        for websocket in sorted(websocket_urls):
            self._add_asset(
                assets,
                "websocket",
                url=websocket
            )

        for parameter in sorted(parameters):
            self._add_asset(
                assets,
                "parameter",
                name=parameter
            )

        for source_map in sorted(source_maps):
            self._add_asset(
                assets,
                "source_map",
                url=source_map
            )

        for documentation in sorted(api_documentation):
            self._add_asset(
                assets,
                "api_documentation",
                url=documentation
            )

        for reference in sorted(auth_references):
            self._add_asset(
                assets,
                "auth_reference",
                url=reference
            )

        for route in sorted(routes):
            self._add_asset(
                assets,
                "application_route",
                url=route
            )

        for worker in sorted(service_workers):
            self._add_asset(
                assets,
                "service_worker",
                url=worker
            )

        # -----------------------------------------------------
        # Final recon object
        # -----------------------------------------------------

        return {
            "target": self.target,
            "urls": sorted(urls),
            "hosts": sorted(hosts),
            "technologies": sorted(technologies),
            "forms": forms,

            "javascript": sorted(javascript_urls),
            "api_endpoints": sorted(api_endpoints),
            "websocket_urls": sorted(websocket_urls),
            "parameters": sorted(parameters),
            "source_maps": sorted(source_maps),

            "api_documentation": sorted(api_documentation),
            "auth_references": sorted(auth_references),
            "routes": sorted(routes),
            "service_workers": sorted(service_workers),

            "cookies": cookies,
            "security_headers": security_headers,

            "assets": assets
        }
