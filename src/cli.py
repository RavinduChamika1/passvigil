# Copyright (c) 2026 Ravindu Chamika | MIT License | Author details: see src/about.py
"""
cli.py - Password Strength & Breach Checker (Week 1 of 52 Weeks of Security)

PROGRAM FLOW
------------
  [1] Check the connection to the breach API
  [2] Ask for the password (hidden input, never echoed or stored)
  [3] Run the analysis with a live progress bar
  [4] Show a clear, colour-coded report
  [5] Offer to check another password

Run:
    python src/cli.py              # full check (strength + breach)
    python src/cli.py --offline    # strength analysis only, no network
    python src/cli.py --fast       # skip the small demo delays
"""

import argparse
import getpass
import sys
import time

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (BarColumn, Progress, SpinnerColumn,
                           TaskProgressColumn, TextColumn)
from rich.table import Table
from rich.text import Text

import about
import breach
import strength

console = Console()

# Colour used for each zxcvbn score (0-4)
SCORE_COLORS = {0: "red", 1: "red", 2: "yellow", 3: "green", 4: "bold green"}


# --------------------------------------------------------------------------
# Small display helpers
# --------------------------------------------------------------------------
def show_banner() -> None:
    console.print(
        Panel.fit(
            "[bold cyan]Password Strength & Breach Checker[/bold cyan]\n"
            "[dim]52 Weeks of Security - Week 1[/dim]\n\n"
            "Your password is analysed on this computer.\n"
            "Only a 5-character hash prefix is sent to the breach API\n"
            "([italic]k-anonymity[/italic]), so the real password never leaves your machine.\n\n"
            f"[dim]© {about.YEAR} {about.AUTHOR} · {about.LICENSE_NAME}[/dim]\n"
            f"[dim]LinkedIn: {about.LINKEDIN}[/dim]",
            border_style="cyan",
            padding=(1, 3),
        )
    )


def strength_bar(score: int) -> str:
    """Turn a 0-4 score into a visual bar, e.g. [###--] ."""
    filled = score + 1  # score 0 still shows one block
    color = SCORE_COLORS[score]
    return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * (5 - filled)}[/dim]"


# --------------------------------------------------------------------------
# Step 1: connection check
# --------------------------------------------------------------------------
def step_check_connection() -> bool:
    """Test the API and report. Returns True if the breach check can run."""
    console.rule("[bold]Step 1 of 4: Checking connection[/bold]")

    with console.status("Contacting api.pwnedpasswords.com ...", spinner="dots"):
        status = breach.check_connection()

    if status.ok:
        console.print(
            f"[green]✔ Connected[/green]  ({status.latency_ms:.0f} ms)  [dim]{status.message}[/dim]\n"
        )
        return True

    console.print(f"[red]✘ Connection failed:[/red] {status.message}")
    console.print(
        "[yellow]You can continue in offline mode (strength analysis only) "
        "or quit and try again.[/yellow]"
    )
    choice = console.input("Continue offline? [bold](y/n)[/bold]: ").strip().lower()
    if choice != "y":
        console.print("Goodbye.")
        sys.exit(1)
    console.print()
    return False


# --------------------------------------------------------------------------
# Step 2: password input
# --------------------------------------------------------------------------
def step_get_password() -> str:
    """Ask for the password without showing it on screen."""
    console.rule("[bold]Step 2 of 4: Enter password[/bold]")
    console.print("[dim]Typing is hidden. The password is never saved or logged.[/dim]")

    while True:
        password = getpass.getpass("Password to check: ")
        if password:
            console.print()
            return password
        console.print("[red]Password cannot be empty. Try again.[/red]")


# --------------------------------------------------------------------------
# Step 3: analysis with progress bar
# --------------------------------------------------------------------------
def step_analyse(password: str, online: bool, fast: bool):
    """Run strength + breach checks while showing a live progress bar."""
    console.rule("[bold]Step 3 of 4: Analysing[/bold]")

    pause = 0 if fast else 0.4   # small delay so each stage is visible in demos
    breach_result = None
    error = None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Starting ...", total=100)

        def update(text: str, advance: int = 0) -> None:
            progress.update(task, description=text, advance=advance)
            time.sleep(pause)

        # Stage 1: strength (local)
        update("Analysing password strength (local)")
        strength_result = strength.analyze(password)
        update("Strength analysis complete", advance=25)

        if online:
            # Stages 2-4: breach lookup. The callback keeps the bar in sync.
            stage_steps = iter([20, 20, 20])

            def on_step(message: str) -> None:
                update(message, advance=next(stage_steps, 0))

            try:
                breach_result = breach.check_password(password, on_step=on_step)
                update("Breach lookup complete")
            except breach.BreachCheckError as exc:
                error = str(exc)
                update("Breach lookup failed")
        else:
            update("Offline mode: skipping breach lookup")

        progress.update(task, completed=100, description="[green]Analysis complete[/green]")

    console.print()
    return strength_result, breach_result, error


# --------------------------------------------------------------------------
# Step 4: report
# --------------------------------------------------------------------------
def step_report(s: strength.StrengthResult, b, error, online: bool) -> None:
    """Display all results in a clean, structured report."""
    console.rule("[bold]Step 4 of 4: Results[/bold]")

    # ---- Strength table ---------------------------------------------------
    color = SCORE_COLORS[s.score]
    table = Table(box=box.ROUNDED, show_header=False, padding=(0, 2), title="Strength Analysis")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Rating", f"[{color}]{s.label}[/{color}]  {strength_bar(s.score)}  ({s.score}/4)")
    table.add_row("Length", f"{s.length} characters")
    table.add_row("Entropy (theoretical)", f"{s.entropy_bits:.1f} bits")
    table.add_row("Crack time (slow hash, e.g. bcrypt)", s.crack_time_offline)
    table.add_row("Crack time (fast hash, e.g. leaked SHA-1)", s.crack_time_fast)
    console.print(table)

    # ---- Checklist --------------------------------------------------------
    checklist = Table(box=box.SIMPLE, show_header=False, title="Character Checklist")
    checklist.add_column("Check")
    checklist.add_column("Result", justify="center")
    for name, passed in s.checks.items():
        checklist.add_row(name, "[green]✔[/green]" if passed else "[red]✘[/red]")
    console.print(checklist)

    # ---- Breach result ----------------------------------------------------
    console.print(Text("Breach Check", style="bold underline"))
    if not online:
        console.print("[yellow]⚠ Skipped (offline mode)[/yellow]")
    elif error:
        console.print(f"[yellow]⚠ Could not complete: {error}[/yellow]")
    elif b.is_pwned:
        console.print(
            f"[bold red]✘ FOUND in data breaches {b.pwned_count:,} times[/bold red]\n"
            "  Attackers already have this password in their wordlists."
        )
    else:
        console.print("[green]✔ Not found in any known breach[/green]")
    if online and b is not None:
        console.print(
            f"[dim]  Privacy: only the prefix '{b.prefix_sent}' was sent; "
            f"{b.candidates} possible hashes were returned and compared locally.[/dim]"
        )
    console.print()

    # ---- Warnings and tips ------------------------------------------------
    if s.warning or s.suggestions:
        tips = []
        if s.warning:
            tips.append(f"[bold]Warning:[/bold] {s.warning}")
        tips.extend(f"• {tip}" for tip in s.suggestions)
        console.print(Panel("\n".join(tips), title="How to improve", border_style="yellow"))

    # ---- Final verdict ----------------------------------------------------
    if b is not None and b.is_pwned:
        verdict, style = "DO NOT USE: this password has been leaked.", "red"
    elif s.score >= 3 and (b is not None or not online):
        verdict, style = "GOOD: strong password" + (" and not found in breaches." if b else "."), "green"
    else:
        verdict, style = "IMPROVE: choose a longer, less predictable password.", "yellow"
    console.print(Panel(f"[bold]{verdict}[/bold]", border_style=style, title="Verdict"))


# --------------------------------------------------------------------------
# Program entry point
# --------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="Password strength and breach checker")
    parser.add_argument("--offline", action="store_true", help="skip the breach lookup (no network)")
    parser.add_argument("--fast", action="store_true", help="skip demo delays in the progress bar")
    args = parser.parse_args()

    show_banner()

    # Step 1: only test the network if we plan to use it
    online = False if args.offline else step_check_connection()
    if args.offline:
        console.print("[yellow]Offline mode: breach lookup disabled.[/yellow]\n")

    try:
        while True:
            password = step_get_password()                          # Step 2
            s, b, err = step_analyse(password, online, args.fast)   # Step 3
            del password                                            # drop the reference early
            step_report(s, b, err, online)                          # Step 4

            again = console.input("\nCheck another password? [bold](y/n)[/bold]: ").strip().lower()
            if again != "y":
                break
            console.print()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[dim]Cancelled.[/dim]")

    console.print("[cyan]Stay safe. Use a password manager and unique passwords.[/cyan]")
    console.print(f"[dim]Built by {about.AUTHOR} · {about.LINKEDIN}[/dim]")


if __name__ == "__main__":
    main()
