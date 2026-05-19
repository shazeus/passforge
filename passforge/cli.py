"""passforge CLI — Secure password and secret generator."""

import sys
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from rich.text import Text
from rich.columns import Columns

from passforge import __version__
from passforge.generator import (
    generate_password,
    generate_passphrase,
    generate_pin,
    generate_token,
    analyze_password,
    check_hibp,
    _strength_label,
    _crack_time_label,
    _entropy,
    WORDLIST,
)

console = Console()
err_console = Console(stderr=True)


def _copy_to_clipboard(text: str) -> bool:
    """Try to copy text to clipboard. Returns True on success."""
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except Exception:
        return False


def _print_password_result(password: str, copy: bool, label: str = "Password") -> None:
    """Print a password result with optional clipboard copy."""
    console.print(f"\n[bold cyan]{label}:[/bold cyan]")
    console.print(f"  [bold white on black] {password} [/bold white on black]")
    if copy:
        if _copy_to_clipboard(password):
            console.print("  [dim green]✓ Copied to clipboard[/dim green]")
        else:
            console.print("  [dim yellow]⚠ Clipboard not available[/dim yellow]")


@click.group()
@click.version_option(__version__, prog_name="passforge")
def cli():
    """passforge — Secure password and secret generator.

    Generate cryptographically secure passwords, passphrases, PINs, tokens,
    and more. Analyze strength, check breach databases, and bulk-generate secrets.
    """
    pass


@cli.command("gen")
@click.option("-l", "--length", default=16, show_default=True, help="Password length.")
@click.option("-n", "--count", default=1, show_default=True, help="Number of passwords to generate.")
@click.option("--no-upper", is_flag=True, help="Exclude uppercase letters.")
@click.option("--no-lower", is_flag=True, help="Exclude lowercase letters.")
@click.option("--no-digits", is_flag=True, help="Exclude digits.")
@click.option("--no-symbols", is_flag=True, help="Exclude symbols.")
@click.option("--no-ambiguous", is_flag=True, help="Exclude ambiguous characters (0,O,1,l,I).")
@click.option("--exclude", default="", help="Additional characters to exclude.")
@click.option("--min-upper", default=0, help="Minimum uppercase letters.")
@click.option("--min-lower", default=0, help="Minimum lowercase letters.")
@click.option("--min-digits", default=0, help="Minimum digits.")
@click.option("--min-symbols", default=0, help="Minimum symbols.")
@click.option("-c", "--copy", is_flag=True, help="Copy first password to clipboard.")
@click.option("--bare", is_flag=True, help="Output passwords only (no decoration).")
def cmd_gen(length, count, no_upper, no_lower, no_digits, no_symbols,
            no_ambiguous, exclude, min_upper, min_lower, min_digits, min_symbols,
            copy, bare):
    """Generate secure random password(s)."""
    if bare:
        for _ in range(count):
            try:
                pw = generate_password(
                    length=length,
                    uppercase=not no_upper,
                    lowercase=not no_lower,
                    digits=not no_digits,
                    symbols=not no_symbols,
                    exclude_ambiguous=no_ambiguous,
                    exclude_chars=exclude,
                    min_uppercase=min_upper,
                    min_lowercase=min_lower,
                    min_digits=min_digits,
                    min_symbols=min_symbols,
                )
                click.echo(pw)
            except ValueError as e:
                err_console.print(f"[red]Error:[/red] {e}")
                sys.exit(1)
        return

    console.print(Panel(
        f"[bold]Generating {count} password{'s' if count > 1 else ''}[/bold] | "
        f"Length: [cyan]{length}[/cyan] | "
        f"Upper: [cyan]{'No' if no_upper else 'Yes'}[/cyan] | "
        f"Lower: [cyan]{'No' if no_lower else 'Yes'}[/cyan] | "
        f"Digits: [cyan]{'No' if no_digits else 'Yes'}[/cyan] | "
        f"Symbols: [cyan]{'No' if no_symbols else 'Yes'}[/cyan]",
        title="[bold cyan]passforge gen[/bold cyan]",
        border_style="cyan",
    ))

    passwords = []
    try:
        for _ in range(count):
            pw = generate_password(
                length=length,
                uppercase=not no_upper,
                lowercase=not no_lower,
                digits=not no_digits,
                symbols=not no_symbols,
                exclude_ambiguous=no_ambiguous,
                exclude_chars=exclude,
                min_uppercase=min_upper,
                min_lowercase=min_lower,
                min_digits=min_digits,
                min_symbols=min_symbols,
            )
            passwords.append(pw)
    except ValueError as e:
        err_console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    if count == 1:
        _print_password_result(passwords[0], copy)
    else:
        table = Table(box=box.ROUNDED, border_style="cyan", show_header=True)
        table.add_column("#", style="dim", width=4)
        table.add_column("Password", style="bold white")
        table.add_column("Length", justify="right", style="cyan")
        for i, pw in enumerate(passwords, 1):
            table.add_row(str(i), pw, str(len(pw)))
        console.print(table)
        if copy:
            if _copy_to_clipboard(passwords[0]):
                console.print("[dim green]✓ First password copied to clipboard[/dim green]")
            else:
                console.print("[dim yellow]⚠ Clipboard not available[/dim yellow]")

    console.print()


@cli.command("passphrase")
@click.option("-w", "--words", default=4, show_default=True, help="Number of words.")
@click.option("-s", "--separator", default="-", show_default=True, help="Word separator.")
@click.option("--capitalize", is_flag=True, help="Capitalize each word.")
@click.option("--no-number", is_flag=True, help="Do not append a random number.")
@click.option("-n", "--count", default=1, show_default=True, help="Number of passphrases.")
@click.option("-c", "--copy", is_flag=True, help="Copy first passphrase to clipboard.")
@click.option("--bare", is_flag=True, help="Output passphrases only.")
def cmd_passphrase(words, separator, capitalize, no_number, count, copy, bare):
    """Generate memorable passphrases from wordlist."""
    if bare:
        for _ in range(count):
            pp = generate_passphrase(
                words=words,
                separator=separator,
                capitalize=capitalize,
                include_number=not no_number,
            )
            click.echo(pp)
        return

    console.print(Panel(
        f"[bold]Generating {count} passphrase{'s' if count > 1 else ''}[/bold] | "
        f"Words: [cyan]{words}[/cyan] | "
        f"Separator: [cyan]{repr(separator)}[/cyan] | "
        f"Capitalize: [cyan]{'Yes' if capitalize else 'No'}[/cyan] | "
        f"Number: [cyan]{'No' if no_number else 'Yes'}[/cyan]",
        title="[bold magenta]passforge passphrase[/bold magenta]",
        border_style="magenta",
    ))

    passphrases = []
    for _ in range(count):
        pp = generate_passphrase(
            words=words,
            separator=separator,
            capitalize=capitalize,
            include_number=not no_number,
        )
        passphrases.append(pp)

    if count == 1:
        _print_password_result(passphrases[0], copy, "Passphrase")
    else:
        table = Table(box=box.ROUNDED, border_style="magenta")
        table.add_column("#", style="dim", width=4)
        table.add_column("Passphrase", style="bold white")
        for i, pp in enumerate(passphrases, 1):
            table.add_row(str(i), pp)
        console.print(table)
        if copy:
            if _copy_to_clipboard(passphrases[0]):
                console.print("[dim green]✓ First passphrase copied to clipboard[/dim green]")
            else:
                console.print("[dim yellow]⚠ Clipboard not available[/dim yellow]")

    console.print()


@cli.command("pin")
@click.option("-l", "--length", default=6, show_default=True, help="PIN length.")
@click.option("-n", "--count", default=1, show_default=True, help="Number of PINs.")
@click.option("-c", "--copy", is_flag=True, help="Copy first PIN to clipboard.")
@click.option("--bare", is_flag=True, help="Output PINs only.")
def cmd_pin(length, count, copy, bare):
    """Generate numeric PINs."""
    if bare:
        for _ in range(count):
            click.echo(generate_pin(length))
        return

    console.print(Panel(
        f"[bold]Generating {count} PIN{'s' if count > 1 else ''}[/bold] | "
        f"Length: [cyan]{length}[/cyan] digits",
        title="[bold yellow]passforge pin[/bold yellow]",
        border_style="yellow",
    ))

    pins = [generate_pin(length) for _ in range(count)]

    if count == 1:
        _print_password_result(pins[0], copy, "PIN")
    else:
        table = Table(box=box.ROUNDED, border_style="yellow")
        table.add_column("#", style="dim", width=4)
        table.add_column("PIN", style="bold white")
        for i, pin in enumerate(pins, 1):
            table.add_row(str(i), pin)
        console.print(table)
        if copy:
            if _copy_to_clipboard(pins[0]):
                console.print("[dim green]✓ First PIN copied to clipboard[/dim green]")

    console.print()


@cli.command("token")
@click.option("-l", "--length", default=32, show_default=True, help="Token length (bytes for hex/base64).")
@click.option("-f", "--format", "fmt",
              type=click.Choice(["hex", "urlsafe", "base64", "alphanumeric", "uuid"]),
              default="hex", show_default=True, help="Token format.")
@click.option("-n", "--count", default=1, show_default=True, help="Number of tokens.")
@click.option("-c", "--copy", is_flag=True, help="Copy first token to clipboard.")
@click.option("--bare", is_flag=True, help="Output tokens only.")
def cmd_token(length, fmt, count, copy, bare):
    """Generate secure random tokens (API keys, secrets, UUIDs)."""
    if bare:
        for _ in range(count):
            try:
                click.echo(generate_token(length, fmt))
            except ValueError as e:
                err_console.print(f"[red]Error:[/red] {e}")
                sys.exit(1)
        return

    console.print(Panel(
        f"[bold]Generating {count} token{'s' if count > 1 else ''}[/bold] | "
        f"Format: [cyan]{fmt}[/cyan] | "
        f"Length: [cyan]{length}[/cyan]",
        title="[bold green]passforge token[/bold green]",
        border_style="green",
    ))

    tokens = []
    try:
        for _ in range(count):
            tokens.append(generate_token(length, fmt))
    except ValueError as e:
        err_console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    if count == 1:
        _print_password_result(tokens[0], copy, "Token")
    else:
        table = Table(box=box.ROUNDED, border_style="green")
        table.add_column("#", style="dim", width=4)
        table.add_column("Token", style="bold white")
        for i, tok in enumerate(tokens, 1):
            table.add_row(str(i), tok)
        console.print(table)
        if copy:
            if _copy_to_clipboard(tokens[0]):
                console.print("[dim green]✓ First token copied to clipboard[/dim green]")

    console.print()


@cli.command("analyze")
@click.argument("password", required=False)
@click.option("--hibp", is_flag=True, help="Check against Have I Been Pwned database.")
@click.option("--no-show", is_flag=True, help="Don't display the password (privacy mode).")
def cmd_analyze(password, hibp, no_show):
    """Analyze password strength and security metrics."""
    if not password:
        try:
            password = click.prompt("Enter password to analyze", hide_input=True)
        except (click.Abort, EOFError):
            console.print("\n[dim]Aborted.[/dim]")
            sys.exit(0)

    analysis = analyze_password(password)

    console.print(Panel(
        "[bold]Password Strength Analysis[/bold]",
        title="[bold blue]passforge analyze[/bold blue]",
        border_style="blue",
    ))

    if not no_show:
        console.print(f"\n[bold]Password:[/bold] [bold white on black] {password} [/bold white on black]")

    strength_color = analysis["strength_color"]
    strength = analysis["strength"]

    # Entropy bar
    entropy = analysis["entropy"]
    bar_full = min(int(entropy / 128 * 40), 40)
    bar = "█" * bar_full + "░" * (40 - bar_full)

    console.print()

    table = Table(box=box.ROUNDED, border_style="blue", show_header=False)
    table.add_column("Metric", style="bold", width=20)
    table.add_column("Value")

    table.add_row("Length", f"[cyan]{analysis['length']}[/cyan] characters")
    table.add_row("Entropy", f"[cyan]{entropy:.1f}[/cyan] bits")
    table.add_row("Entropy Bar", f"[{strength_color}]{bar}[/{strength_color}]")
    table.add_row("Strength", f"[{strength_color}]{strength}[/{strength_color}]")
    table.add_row("Est. Crack Time", f"[yellow]{analysis['crack_time']}[/yellow]")
    table.add_row("Charset Size", f"[cyan]{analysis['charset_size']}[/cyan] characters")

    char_types = []
    if analysis["has_lowercase"]:
        char_types.append("[green]Lowercase[/green]")
    else:
        char_types.append("[dim]Lowercase[/dim]")
    if analysis["has_uppercase"]:
        char_types.append("[green]Uppercase[/green]")
    else:
        char_types.append("[dim]Uppercase[/dim]")
    if analysis["has_digits"]:
        char_types.append("[green]Digits[/green]")
    else:
        char_types.append("[dim]Digits[/dim]")
    if analysis["has_symbols"]:
        char_types.append("[green]Symbols[/green]")
    else:
        char_types.append("[dim]Symbols[/dim]")

    table.add_row("Character Types", "  ".join(char_types))

    if analysis["has_ambiguous"]:
        table.add_row("Ambiguous Chars", "[yellow]⚠ Contains ambiguous characters (0,O,1,l,I)[/yellow]")

    if analysis["patterns"]:
        table.add_row("Patterns Found", "[red]⚠ " + ", ".join(analysis["patterns"]) + "[/red]")
    else:
        table.add_row("Patterns", "[green]✓ No common patterns detected[/green]")

    console.print(table)

    if hibp:
        console.print()
        with console.status("[bold]Checking Have I Been Pwned...[/bold]"):
            count = check_hibp(analysis["sha1_prefix"], analysis["sha1_suffix"])

        if count is None:
            console.print("[yellow]⚠ Could not reach HIBP API (network error)[/yellow]")
        elif count == 0:
            console.print("[green]✓ Not found in any known data breaches[/green]")
        else:
            console.print(f"[red]✗ Found in [bold]{count:,}[/bold] data breach(es)! Do not use this password.[/red]")

    console.print()


@cli.command("bulk")
@click.option("-n", "--count", default=10, show_default=True, help="Number of passwords to generate.")
@click.option("-l", "--length", default=16, show_default=True, help="Password length.")
@click.option("-t", "--type",
              type=click.Choice(["password", "passphrase", "pin", "token"]),
              default="password", show_default=True, help="Type of secret to generate.")
@click.option("--no-symbols", is_flag=True, help="Exclude symbols (for passwords).")
@click.option("--no-ambiguous", is_flag=True, help="Exclude ambiguous characters.")
@click.option("-w", "--words", default=4, show_default=True, help="Words per passphrase.")
@click.option("-f", "--format", "fmt",
              type=click.Choice(["hex", "urlsafe", "base64", "alphanumeric", "uuid"]),
              default="hex", show_default=True, help="Token format.")
@click.option("-o", "--output", type=click.Path(), help="Save to file instead of stdout.")
@click.option("--with-strength", is_flag=True, help="Include strength analysis (passwords only).")
def cmd_bulk(count, length, type, no_symbols, no_ambiguous, words, fmt, output, with_strength):
    """Generate multiple secrets in bulk."""
    if output:
        console.print(Panel(
            f"[bold]Bulk generating {count} {type}s[/bold] → [cyan]{output}[/cyan]",
            title="[bold bright_blue]passforge bulk[/bold bright_blue]",
            border_style="bright_blue",
        ))
    else:
        console.print(Panel(
            f"[bold]Bulk generating {count} {type}s[/bold]",
            title="[bold bright_blue]passforge bulk[/bold bright_blue]",
            border_style="bright_blue",
        ))

    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}[/bold blue]"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Generating {count} {type}s...", total=count)
        for _ in range(count):
            if type == "password":
                r = generate_password(
                    length=length,
                    symbols=not no_symbols,
                    exclude_ambiguous=no_ambiguous,
                )
            elif type == "passphrase":
                r = generate_passphrase(words=words)
            elif type == "pin":
                r = generate_pin(length)
            elif type == "token":
                r = generate_token(length, fmt)
            results.append(r)
            progress.advance(task)

    if output:
        lines = []
        for i, r in enumerate(results, 1):
            if with_strength and type == "password":
                analysis = analyze_password(r)
                lines.append(f"{r}\t# {analysis['strength']} ({analysis['entropy']:.0f} bits)")
            else:
                lines.append(r)
        with open(output, "w") as f:
            f.write("\n".join(lines) + "\n")
        console.print(f"\n[green]✓ Saved {count} {type}s to [bold]{output}[/bold][/green]")
    else:
        if with_strength and type == "password":
            table = Table(box=box.ROUNDED, border_style="bright_blue")
            table.add_column("#", style="dim", width=4)
            table.add_column("Password", style="bold white")
            table.add_column("Strength")
            table.add_column("Entropy", justify="right")
            for i, r in enumerate(results, 1):
                analysis = analyze_password(r)
                strength_color = analysis["strength_color"]
                table.add_row(
                    str(i), r,
                    f"[{strength_color}]{analysis['strength']}[/{strength_color}]",
                    f"[cyan]{analysis['entropy']:.0f}[/cyan] bits",
                )
        else:
            table = Table(box=box.ROUNDED, border_style="bright_blue")
            table.add_column("#", style="dim", width=4)
            table.add_column("Value", style="bold white")
            for i, r in enumerate(results, 1):
                table.add_row(str(i), r)
        console.print(table)

    console.print()


@cli.command("strength")
@click.option("-l", "--length", default=12, show_default=True, help="Password length to evaluate.")
@click.option("--charset-lower", is_flag=True, help="Include lowercase only.")
def cmd_strength(length, charset_lower):
    """Show entropy table for various password configurations."""
    console.print(Panel(
        f"[bold]Entropy Reference Table[/bold] for length [cyan]{length}[/cyan]",
        title="[bold bright_yellow]passforge strength[/bold bright_yellow]",
        border_style="bright_yellow",
    ))

    configs = [
        ("Numeric (PIN)", 10),
        ("Lowercase alpha", 26),
        ("Alpha (mixed case)", 52),
        ("Alphanumeric", 62),
        ("Alphanumeric + Symbols", 94),
        ("Full printable ASCII", 95),
        ("Hex (0-9, a-f)", 16),
        ("Base64 characters", 64),
    ]

    table = Table(box=box.ROUNDED, border_style="bright_yellow")
    table.add_column("Character Set", style="bold")
    table.add_column("Charset Size", justify="right", style="cyan")
    table.add_column("Entropy (bits)", justify="right")
    table.add_column("Strength")
    table.add_column("Est. Crack Time", style="yellow")

    for name, size in configs:
        entropy = _entropy(size, length)
        label, color = _strength_label(entropy)
        crack = _crack_time_label(entropy)
        table.add_row(
            name,
            str(size),
            f"[cyan]{entropy:.1f}[/cyan]",
            f"[{color}]{label}[/{color}]",
            crack,
        )

    console.print(table)

    console.print(f"\n[dim]Assumption: 10 billion guesses/second (modern GPU cluster)[/dim]")
    console.print(f"[dim]Recommendation: Use ≥80 bits of entropy for sensitive accounts[/dim]")
    console.print()


@cli.command("recipe")
@click.option("--profile",
              type=click.Choice(["basic", "secure", "max", "web", "api", "wifi", "pin", "passphrase"]),
              default=None, help="Use a preset profile.")
@click.option("-c", "--copy", is_flag=True, help="Copy to clipboard.")
def cmd_recipe(profile, copy):
    """Generate passwords using recommended security profiles."""
    profiles = {
        "basic": {
            "desc": "Basic account — social media, low-risk",
            "length": 12, "symbols": True, "ambiguous": False,
            "type": "password",
        },
        "secure": {
            "desc": "Secure account — email, banking, work",
            "length": 20, "symbols": True, "ambiguous": True,
            "type": "password",
        },
        "max": {
            "desc": "Maximum security — admin, root, vault",
            "length": 32, "symbols": True, "ambiguous": False,
            "type": "password",
        },
        "web": {
            "desc": "Web service — avoids problematic symbols",
            "length": 16, "symbols": False, "ambiguous": False,
            "type": "password",
        },
        "api": {
            "desc": "API key / secret token (hex)",
            "type": "token", "length": 32, "fmt": "hex",
        },
        "wifi": {
            "desc": "WiFi password — easy to type",
            "type": "passphrase", "words": 4, "separator": "-",
        },
        "pin": {
            "desc": "Numeric PIN",
            "type": "pin", "length": 6,
        },
        "passphrase": {
            "desc": "Memorable passphrase (4 words)",
            "type": "passphrase", "words": 4,
        },
    }

    if profile is None:
        console.print(Panel(
            "[bold]Available Security Profiles[/bold]",
            title="[bold bright_magenta]passforge recipe[/bold bright_magenta]",
            border_style="bright_magenta",
        ))
        table = Table(box=box.ROUNDED, border_style="bright_magenta")
        table.add_column("Profile", style="bold cyan")
        table.add_column("Description")
        table.add_column("Details")
        for pname, pdata in profiles.items():
            details = pdata.get("desc", "")
            table.add_row(pname, details, "")
        console.print(table)
        console.print(f"\nRun with [bold]--profile <name>[/bold] to generate.")
        return

    pdata = profiles[profile]
    ptype = pdata["type"]

    console.print(Panel(
        f"[bold]{pdata['desc']}[/bold]",
        title=f"[bold bright_magenta]passforge recipe — {profile}[/bold bright_magenta]",
        border_style="bright_magenta",
    ))

    if ptype == "password":
        pw = generate_password(
            length=pdata["length"],
            symbols=pdata["symbols"],
            exclude_ambiguous=not pdata["ambiguous"],
        )
        _print_password_result(pw, copy)
        analysis = analyze_password(pw)
        color = analysis["strength_color"]
        console.print(
            f"  Strength: [{color}]{analysis['strength']}[/{color}] | "
            f"Entropy: [cyan]{analysis['entropy']:.0f}[/cyan] bits | "
            f"Crack: [yellow]{analysis['crack_time']}[/yellow]"
        )
    elif ptype == "token":
        tok = generate_token(pdata["length"], pdata["fmt"])
        _print_password_result(tok, copy, "Token")
    elif ptype == "passphrase":
        pp = generate_passphrase(words=pdata["words"])
        _print_password_result(pp, copy, "Passphrase")
    elif ptype == "pin":
        pin = generate_pin(pdata["length"])
        _print_password_result(pin, copy, "PIN")

    console.print()
