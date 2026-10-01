import click
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from pathlib import Path
from .core.programs import (
    add_program,
    list_programs,
    add_program_target,
    target_in_program
)
from .scanners.tls import TLSScanner
from .scanners.dns import DNSScanner
from .scanners.javascript import JavaScriptScanner
from .modules.tls_security import analyze as analyze_tls
from .core.config import get_config
from .core.scope import add_scope, list_scope, is_in_scope
from .core.storage import add_finding, get_findings
from .core.recon_storage import (
    create_workspace,
    save_recon,
    save_http_results,
    save_nmap_result,
    save_json
)

from .scanners.http import HTTPScanner
from .scanners.nmap import NmapScanner


from .modules.headers import analyze as analyze_headers
from .modules.exposure import analyze as analyze_exposure
from .modules.web_security import analyze as analyze_web_security

from .engine.planner import Planner
from .engine.analyzer import Analyzer
from .engine.vulnerability import VulnerabilityEngine
from .engine.verifier import verify_finding, apply_evidence_gate
from .engine.exploitability import exploitability_engine
from .engine.verifier_registry import register_builtin_verifiers
from .engine.active_mode import active_mode
from .engine.recon import ReconEngine
from .modules.finding_engine import analyze_recon
from .modules.auth_security import analyze as analyze_auth_security
from .modules.parameter_security import analyze as analyze_parameter_security
from .modules.injection_indicators import analyze as analyze_injection_indicators
from .modules.vulnerability_signatures import analyze as analyze_vulnerability_signatures
from .modules.passive_security import analyze as analyze_passive_security
from .modules.modern_security import analyze as analyze_modern_security
from .modules.endpoint_intelligence import analyze as analyze_endpoint_intelligence


from .reports.reporter import Reporter


@click.group()
def cli():
    """BugBrain - modular bug bounty research assistant."""
    pass


console = Console()

register_builtin_verifiers()


@cli.command("scope-add")
@click.argument("target")
def scope_add_command(target):
    """Add an authorized target to scope."""

    try:
        added = add_scope(target)
    except ValueError as exc:
        raise click.ClickException(str(exc))

    if added:
        console.print(
            f"[green]Added to scope:[/green] {target}"
        )
    else:
        console.print(
            f"[yellow]Already in scope:[/yellow] {target}"
        )


@cli.command("scope-list")
def scope_list_command():
    """List authorized targets."""

    scopes = list_scope()

    if not scopes:
        console.print("No targets in scope.")
        return

    for target in scopes:
        console.print(f"- {target}")


@cli.command("scan")
@click.argument("target")
@click.option(
    "--program",
    default=None,
    help="Bug-bounty program to use."
)
@click.option(
    "--active",
    is_flag=True,
    default=False,
    help="Enable password-protected active verification."
)
def scan_command(target, program, active):
    """Run safe reconnaissance against an authorized target."""

    if program:

        if not target_in_program(
            program,
            target
        ):

            raise click.ClickException(
                f"Target {target} is not authorized "
                f"for program '{program}'."
            )

    elif not is_in_scope(target):

        raise click.ClickException(
            "Target is not in scope. Add it first with "
            f"'python -m bugbrain scope-add {target}' "
            "or use --program."
        )

    # ---------------------------------------------------------
    # Active Verification Mode
    # ---------------------------------------------------------
    #
    # Normal scans remain passive.
    #
    # --active requires the configured password before any
    # active verifier can be executed.
    #

    if active:

        result = active_mode.activate()

        if not result.enabled:
            raise click.ClickException(
                result.reason
            )

        console.print(
            "[bold yellow]"
            "[!] Active Verification Mode enabled."
            "[/bold yellow]"
        )

    config = get_config()

    workspace = create_workspace(
        target
    )

    console.print(
        f"[dim]Workspace: {workspace}[/dim]"
    )

    console.print(
        f"\n[bold cyan]BugBrain scanning:[/bold cyan] {target}\n"
    )

    planner = Planner(config)

    tasks = planner.choose_tasks()

    console.print(
        "[bold]Tasks:[/bold] "
        + ", ".join(tasks)
    )

    all_findings = []
    http_results = []
    nmap_result = {
        "ok": False,
        "ports": []
    }

    # ---------------------------------------------------------
    # Network reconnaissance
    # ---------------------------------------------------------

    if "nmap" in tasks:

        console.print(
            "\n[bold blue][+] Network reconnaissance...[/bold blue]"
        )

        nmap_result = NmapScanner().scan(target)

        save_nmap_result(
            workspace,
            nmap_result
        )

        if nmap_result.get("error"):

            console.print(
                f"[red]{nmap_result['error']}[/red]"
            )

        else:

            for port in nmap_result.get(
                "ports",
                []
            ):

                console.print(
                    f"    {port['port']}/"
                    f"{port['protocol']} "
                    f"{port.get('service', '')}"
                )

    # ---------------------------------------------------------
    # HTTP discovery
    # ---------------------------------------------------------

    if "http" in tasks:

        console.print(
            "\n[bold blue][+] HTTP discovery...[/bold blue]"
        )

        web_services = {
            "http",
            "https",
            "http-alt",
            "http-proxy",
            "https-alt"
        }

        web_ports = [
            item["port"]
            for item in nmap_result.get(
                "ports",
                []
            )
            if (
                item.get("service", "").lower()
                in web_services
            )
        ]

        # Fallback for cases where Nmap did not identify
        # a service but common web ports are open.
        if not web_ports:

            common_web_ports = {
                80,
                443,
                8000,
                8080,
                8443
            }

            web_ports = [
                item["port"]
                for item in nmap_result.get(
                    "ports",
                    []
                )
                if item["port"] in common_web_ports
            ]

        scanner = HTTPScanner(
            timeout=config["settings"]["timeout"],
            user_agent=config["settings"]["user_agent"]
        )

        http_results = scanner.scan(
            target,
            ports=web_ports
        )

        save_http_results(
            workspace,
            http_results
        )

        # DNS reconnaissance
        dns_scanner = DNSScanner()
        dns_result = dns_scanner.scan(target)

        save_json(
            workspace,
            "dns.json",
            dns_result
        )

        if dns_result.get("ok"):
            console.print(
                "\n[bold cyan]DNS reconnaissance[/bold cyan]"
            )

            console.print(
                f"    Addresses: {', '.join(dns_result.get('addresses', []))}"
            )

            if dns_result.get("canonical_name"):
                console.print(
                    f"    Canonical: {dns_result['canonical_name']}"
                )

        # JavaScript/API reconnaissance
        javascript_results = []

        js_scanner = JavaScriptScanner(
            timeout=config["settings"]["timeout"],
            user_agent=config["settings"]["user_agent"]
        )

        for http_result in http_results:
            if http_result.get("error"):
                continue

            page_url = http_result.get("url", "")

            if not page_url:
                continue

            js_result = js_scanner.scan(page_url)

            if js_result.get("ok"):
                javascript_results.append(js_result)

        save_json(
            workspace,
            "javascript.json",
            javascript_results
        )

        if javascript_results:
            total_scripts = sum(
                len(item.get("scripts", []))
                for item in javascript_results
            )

            total_apis = sum(
                len(item.get("api_endpoints", []))
                for item in javascript_results
            )

            console.print(
                "\n[bold yellow]JavaScript/API reconnaissance[/bold yellow]"
            )

            console.print(
                f"    JavaScript files: {total_scripts}"
            )

            console.print(
                f"    API candidates: {total_apis}"
            )

        # TLS analysis
        tls_results = []

        https_ports = []

        for result in nmap_result.get("ports", []):
            port = result.get("port")
            service = result.get("service", "").lower()

            if port == 443 or service in ("https", "https-alt"):
                https_ports.append(port)

        if not https_ports:
            https_ports = [443, 8443]

        tls_scanner = TLSScanner()

        for port in sorted(set(https_ports)):
            tls_result = tls_scanner.scan(target, port)

            if tls_result.get("ok"):
                tls_results.append(tls_result)

                tls_findings = analyze_tls(
                    target,
                    tls_result
                )

                for finding in tls_findings:
                    finding["port"] = port
                    add_finding(finding)

        save_json(
            workspace,
            "tls.json",
            tls_results
        )

        

        for result in http_results:

            if result.get("error"):
                console.print(
                    f"    [red]{result['error']}[/red]"
                )
                continue

            console.print(
                f"    [green]{result['status']}[/green] "
                f"{result['url']}"
            )

            if result.get("title"):
                console.print(
                    f"    Title: {result['title']}"
                )

            technologies = result.get(
                "technologies",
                []
            )

            if technologies:

                console.print(
                    "    Technologies: "
                    + ", ".join(technologies)
                )

            console.print(
                f"    Links: "
                f"{len(result.get('links', []))}"
            )

            console.print(
                f"    Forms: "
                f"{len(result.get('forms', []))}"
            )

    # ---------------------------------------------------------
    # Recon correlation
    # ---------------------------------------------------------

    if http_results:

        console.print(
            "\n[bold magenta]Recon correlation[/bold magenta]"
        )

        recon = ReconEngine(
            target,
            http_results,
            javascript_results
        ).build()

        console.print(
            f"    URLs: {len(recon['urls'])}"
        )

        console.print(
            f"    Hosts: {len(recon['hosts'])}"
        )

        console.print(
            f"    Forms: {len(recon['forms'])}"
        )

        recon_path = save_recon(
            target,
            recon,
            workspace
        )

        console.print(
            f"    Recon saved: {recon_path}"
        )

        candidate_findings = analyze_recon(
            recon
        )

        for finding in candidate_findings:

            finding["target"] = target

            all_findings.append(
                finding
            )

        # ---------------------------------------------------------
        # Vulnerability correlation
        # ---------------------------------------------------------

        console.print(
            "\n[bold red][+] Vulnerability correlation...[/bold red]"
        )

        vulnerability_engine = VulnerabilityEngine()

        vulnerability_findings = vulnerability_engine.analyze(
            target=target,
            recon=recon,
            http_results=http_results,
            tls_results=tls_results,
            javascript_results=javascript_results
        )

        all_findings.extend(
            vulnerability_findings
        )

        console.print(
            f"    Candidates: {len(vulnerability_findings)}"
        )

        # ---------------------------------------------------------
        # Authentication & access-control analysis
        # ---------------------------------------------------------

        console.print(
            "\n[bold red][+] Authentication & access-control analysis...[/bold red]"
        )

        auth_findings = analyze_auth_security(
            target,
            recon,
            http_results
        )

        all_findings.extend(
            auth_findings
        )

        console.print(
            f"    Candidates: {len(auth_findings)}"
        )

        # ---------------------------------------------------------
        # Parameter & input analysis
        # ---------------------------------------------------------

        console.print(
            "\n[bold red][+] Parameter & input analysis...[/bold red]"
        )

        parameter_findings = analyze_parameter_security(
            target,
            recon,
            javascript_results
        )

        all_findings.extend(
            parameter_findings
        )

        console.print(
            f"    Candidates: {len(parameter_findings)}"
        )

        # ---------------------------------------------------------
        # Safe injection indicators
        # ---------------------------------------------------------

        console.print(
            "\n[bold red][+] Injection/XSS/SSRF indicators...[/bold red]"
        )

        injection_findings = analyze_injection_indicators(
            target,
            recon
        )

        all_findings.extend(
            injection_findings
        )

        console.print(
            f"    Candidates: {len(injection_findings)}"
        )

        passive_findings = analyze_passive_security(
            target,
            http_results
        )

        all_findings.extend(
            passive_findings
        )

        console.print(
            "\n[bold blue][+] Passive security analysis...[/bold blue]"
        )

        console.print(
            f"    Candidates: {len(passive_findings)}"
        )

        modern_findings = analyze_modern_security(
            target,
            http_results,
            recon
        )

        all_findings.extend(
            modern_findings
        )

        console.print(
            "\n[bold magenta][+] Modern API/security analysis...[/bold magenta]"
        )

        console.print(
            f"    Candidates: {len(modern_findings)}"
        )

        endpoint_findings = analyze_endpoint_intelligence(
            target,
            recon,
            http_results
        )

        all_findings.extend(
            endpoint_findings
        )

        console.print(
            "\n[bold cyan][+] Endpoint intelligence analysis...[/bold cyan]"
        )

        console.print(
            f"    Candidates: {len(endpoint_findings)}"
        )

        console.print(
            "\n[bold red][+] Extended vulnerability signature analysis...[/bold red]"
        )

        signature_findings = analyze_vulnerability_signatures(
            target,
            recon,
            http_results,
            javascript_results
        )

        all_findings.extend(
            signature_findings
        )

        console.print(
            f"    Candidates: {len(signature_findings)}"
        )

    # ---------------------------------------------------------
    # Security headers
    # ---------------------------------------------------------

    if "headers" in tasks:

        console.print(
            "\n[bold blue][+] Security header analysis...[/bold blue]"
        )

        for result in http_results:

            if result.get("error"):
                continue

            findings = analyze_headers(
                target,
                result
            )

            all_findings.extend(
                findings
            )

    # ---------------------------------------------------------
    # Exposure checks
    # ---------------------------------------------------------

    if "exposure" in tasks:

        console.print(
            "\n[bold blue][+] Exposure checks...[/bold blue]"
        )

        checked_origins = set()

        for result in http_results:

            if result.get("error"):
                continue

            result_url = str(result.get("url", "")).strip()

            if not result_url:
                continue

            try:
                parsed = urlparse(result_url)

                if parsed.scheme not in ("http", "https"):
                    continue

                if not parsed.netloc:
                    continue

                origin = f"{parsed.scheme}://{parsed.netloc}"

            except Exception:
                continue

            if origin in checked_origins:
                continue

            checked_origins.add(origin)

            findings = analyze_exposure(
                target,
                origin,
                timeout=config["settings"]["timeout"]
            )

            all_findings.extend(
                findings
            )

        # ---------------------------------------------------------
    # Web security checks
    # ---------------------------------------------------------

    if http_results:

        console.print(
            "\n[bold blue][+] Web security checks...[/bold blue]"
        )

        for result in http_results:

            if result.get("error"):
                continue

            findings = analyze_web_security(
                target,
                result
            )

            all_findings.extend(
                findings
            )

    # ---------------------------------------------------------
    # Analyze and store findings
    # ---------------------------------------------------------

    analyzer = Analyzer()

    analyzed_findings = analyzer.analyze(
        all_findings
    )

    # ---------------------------------------------------------
    # Evidence-based verification
    # ---------------------------------------------------------

    console.print(
        "\n[bold cyan][+] Evidence verification...[/bold cyan]"
    )

    exploitability_assessed = []

    if active:
        active_candidates = [
            finding
            for finding in analyzed_findings
            if exploitability_engine.supported(
                str(finding.get("type", ""))
            )
            and exploitability_engine.is_active(
                str(finding.get("type", ""))
            )
        ]

        console.print(
            f"    [bold yellow]Active verification candidates: "
            f"{len(active_candidates)}[/bold yellow]"
        )

        if not active_candidates:
            console.print(
                "    [dim]No findings currently have an active "
                "verifier registered.[/dim]"
            )

    for finding in analyzed_findings:

        finding = dict(finding)

        if active:
            exploitability = exploitability_engine.assess_active(
                finding
            )
        else:
            exploitability = exploitability_engine.assess(
                finding
            )

        finding["exploitability"] = exploitability

        exploitability_assessed.append(
            finding
        )

    analyzed_findings = exploitability_assessed

    verified_findings = []

    for finding in analyzed_findings:

        verified = verify_finding(
            finding
        )

        # -----------------------------------------------------
        # STRUCTURED EVIDENCE GATE
        # -----------------------------------------------------
        #
        # The normal verifier determines whether a finding has
        # enough evidence. The evidence gate performs one final
        # safety check before anything can become confirmed.
        #

        verified = apply_evidence_gate(
            verified
        )

        # -----------------------------------------------------
        # HARD CONFIRMATION GATE
        # -----------------------------------------------------
        #
        # A finding can only become confirmed when the verifier
        # explicitly returned "confirmed".
        #
        # Scanner/module output is NEVER trusted as confirmation.
        #

        if verified.get("status") != "confirmed":
            verified["status"] = "candidate"

        verified_findings.append(
            verified
        )

    confirmed_count = sum(
        1
        for finding in verified_findings
        if finding.get("status") == "confirmed"
    )

    candidate_count = sum(
        1
        for finding in verified_findings
        if finding.get("status") == "candidate"
    )

    console.print(
        f"    [bold green]Confirmed findings: {confirmed_count}[/bold green]"
    )

    console.print(
        f"    [yellow]Candidates requiring verification: {candidate_count}[/yellow]"
    )

    # ---------------------------------------------------------
    # Confirmed-only storage
    # ---------------------------------------------------------

    confirmed_findings = [
        finding
        for finding in verified_findings
        if finding.get("status") == "confirmed"
    ]

    console.print(
        f"    Stored confirmed findings: "
        f"{len(confirmed_findings)}"
    )

    stored_findings = []

    for finding in confirmed_findings:

        stored = add_finding(
            finding
        )

        stored_findings.append(
            stored
        )

    # ---------------------------------------------------------
    # Candidate findings from this scan
    # ---------------------------------------------------------

    candidate_findings = [
        finding
        for finding in verified_findings
        if finding.get("status") == "candidate"
    ]

    if candidate_findings:
        candidate_table = Table(
            title="BugBrain Candidates — Verification Required"
        )

        candidate_table.add_column(
            "Severity",
            style="yellow"
        )

        candidate_table.add_column(
            "Type"
        )

        candidate_table.add_column(
            "Title"
        )

        candidate_table.add_column(
            "URL"
        )

        for finding in candidate_findings:
            candidate_table.add_row(
                finding.get(
                    "severity",
                    "info"
                ),
                finding.get(
                    "type",
                    ""
                ),
                finding.get(
                    "title",
                    ""
                ),
                finding.get(
                    "url",
                    ""
                ),
            )

        console.print(candidate_table)

    # ---------------------------------------------------------
    # Findings table
    # ---------------------------------------------------------

    console.print(
        f"\n[bold yellow]Findings:[/bold yellow] "
        f"{len(stored_findings)}"
    )

    if stored_findings:

        table = Table(
            title="BugBrain Findings"
        )

        table.add_column(
            "ID",
            style="cyan"
        )

        table.add_column(
            "Severity",
            style="yellow"
        )

        table.add_column(
            "Type"
        )

        table.add_column(
            "Title"
        )

        for finding in stored_findings:

            table.add_row(
                str(finding.get("id", "")),
                finding.get(
                    "severity",
                    "info"
                ),
                finding.get(
                    "type",
                    ""
                ),
                finding.get(
                    "title",
                    ""
                )
            )

        console.print(table)

    # ---------------------------------------------------------
    # Report
    # ---------------------------------------------------------

    reporter = Reporter()

    report_path = reporter.generate(
        target,
        stored_findings,
        workspace
    )

    console.print(
        f"\n[bold green][+] Report:[/bold green] "
        f"{report_path}"
    )


@cli.command("findings")
def findings_command():
    """Show stored findings."""

    findings = get_findings()

    if not findings:

        console.print(
            "No stored findings."
        )

        return

    table = Table(
        title="Stored Findings"
    )

    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Target")
    table.add_column("Title")

    for finding in findings:

        table.add_row(
            str(finding.get("id", "")),
            finding.get(
                "severity",
                "info"
            ),
            finding.get(
                "target",
                ""
            ),
            finding.get(
                "title",
                ""
            )
        )

    console.print(table)


@cli.command("runs")
def runs_command():
    """List previous BugBrain scan runs."""

    workspaces = Path("workspaces")

    if not workspaces.exists():
        console.print("No scan runs found.")
        return

    runs = []

    for target_dir in workspaces.iterdir():

        if not target_dir.is_dir():
            continue

        for run_dir in target_dir.iterdir():

            if not run_dir.is_dir():
                continue

            report_files = list(
                run_dir.glob("bugbrain-*.md")
            )

            runs.append({
                "target": target_dir.name,
                "run": run_dir.name,
                "path": str(run_dir),
                "report": (
                    str(report_files[0])
                    if report_files
                    else "-"
                )
            })

    if not runs:
        console.print("No scan runs found.")
        return

    runs.sort(
        key=lambda item: (
            item["target"],
            item["run"]
        ),
        reverse=True
    )

    table = Table(
        title="BugBrain Scan History"
    )

    table.add_column("Target")
    table.add_column("Run")
    table.add_column("Report")

    for item in runs:

        table.add_row(
            item["target"],
            item["run"],
            item["report"]
        )

    console.print(table)

@cli.command("run-show")
@click.argument("target")
@click.argument("run")
def run_show_command(target, run):
    """Show details from a previous scan run."""

    workspace = (
        Path("workspaces")
        / target
        / run
    )

    if not workspace.exists():
        raise click.ClickException(
            f"Run not found: {workspace}"
        )

    console.print(
        f"\n[bold cyan]Run:[/bold cyan] {run}"
    )

    console.print(
        f"[bold]Target:[/bold] {target}"
    )

    console.print(
        f"[bold]Workspace:[/bold] {workspace}\n"
    )

    # ---------------------------------------------------------
    # Nmap
    # ---------------------------------------------------------

    nmap_file = workspace / "nmap.json"

    if nmap_file.exists():

        import json

        nmap_data = json.loads(
            nmap_file.read_text(
                encoding="utf-8"
            )
        )

        console.print(
            "[bold blue]Open Ports[/bold blue]"
        )

        for port in nmap_data.get(
            "ports",
            []
        ):

            console.print(
                f"  {port.get('port')}/"
                f"{port.get('protocol')} "
                f"{port.get('service', '')}"
            )

    # ---------------------------------------------------------
    # HTTP
    # ---------------------------------------------------------

    http_file = workspace / "http.json"

    if http_file.exists():

        import json

        http_data = json.loads(
            http_file.read_text(
                encoding="utf-8"
            )
        )

        console.print(
            "\n[bold blue]Web Services[/bold blue]"
        )

        for result in http_data:

            console.print(
                f"  {result.get('status')} "
                f"{result.get('url')}"
            )

            if result.get("title"):
                console.print(
                    f"    Title: "
                    f"{result['title']}"
                )

            if result.get(
                "technologies"
            ):

                console.print(
                    "    Technologies: "
                    + ", ".join(
                        result["technologies"]
                    )
                )

    # ---------------------------------------------------------
    # Recon
    # ---------------------------------------------------------

    recon_file = workspace / "recon.json"

    if recon_file.exists():

        import json

        recon = json.loads(
            recon_file.read_text(
                encoding="utf-8"
            )
        )

        console.print(
            "\n[bold blue]Recon[/bold blue]"
        )

        console.print(
            f"  URLs: "
            f"{len(recon.get('urls', []))}"
        )

        console.print(
            f"  Hosts: "
            f"{len(recon.get('hosts', []))}"
        )

        console.print(
            f"  Forms: "
            f"{len(recon.get('forms', []))}"
        )

        console.print(
            f"  Technologies: "
            f"{len(recon.get('technologies', []))}"
        )

    # ---------------------------------------------------------
    # Report
    # ---------------------------------------------------------

    reports = list(
        workspace.glob(
            "bugbrain-*.md"
        )
    )

    if reports:

        report = sorted(
            reports,
            reverse=True
        )[0]

        console.print(
            "\n[bold green]Report:[/bold green]"
        )

        console.print(
            f"  {report}"
        )

@cli.command("program-add")
@click.argument("name")
@click.option(
    "--platform",
    default="custom",
    help="Program platform."
)
def program_add_command(name, platform):
    """Add a bug-bounty program."""

    if add_program(name, platform):
        console.print(
            f"[green]Program added:[/green] {name}"
        )
    else:
        console.print(
            f"[yellow]Program already exists:[/yellow] {name}"
        )


@cli.command("program-list")
def program_list_command():
    """List bug-bounty programs."""

    programs = list_programs()

    if not programs:
        console.print(
            "No programs configured."
        )
        return

    table = Table(
        title="BugBrain Programs"
    )

    table.add_column("Program")
    table.add_column("Platform")
    table.add_column("Targets")

    for program in programs:

        table.add_row(
            program["name"],
            program.get(
                "platform",
                "custom"
            ),
            str(
                len(
                    program.get(
                        "targets",
                        []
                    )
                )
            )
        )

    console.print(table)


@cli.command("program-target-add")
@click.argument("program")
@click.argument("target")
def program_target_add_command(
    program,
    target
):
    """Add an authorized target to a program."""

    if add_program_target(
        program,
        target
    ):

        console.print(
            f"[green]Target added:[/green] "
            f"{target}"
        )

    else:

        raise click.ClickException(
            f"Program not found: {program}"
        )

def main():
    cli()


if __name__ == "__main__":
    main()
