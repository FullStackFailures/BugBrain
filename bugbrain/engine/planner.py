from ..core.runner import ToolRunner


class Planner:

    def __init__(self, config):
        self.config = config
        self.tools = ToolRunner.installed_tools()

    def available_capabilities(self):
        capabilities = set()

        for tool in self.tools:
            if not tool.get("installed"):
                continue

            if not tool.get("enabled", True):
                continue

            for capability in tool.get("capabilities", []):
                capabilities.add(capability)

        return sorted(capabilities)

    def choose_tasks(self):
        modules = self.config.get("modules", {})

        tasks = []

        if modules.get("dns", True):
            tasks.append("dns")

        if modules.get("http", True):
            tasks.append("http")

        if modules.get("headers", True):
            tasks.append("headers")

        if modules.get("exposure", True):
            tasks.append("exposure")

        if modules.get("tls", True):
            tasks.append("tls")

        if modules.get("javascript", True):
            tasks.append("javascript")

        capabilities = self.available_capabilities()

        if "port_scan" in capabilities:
            if modules.get("nmap", True):
                tasks.append("nmap")

        return tasks
