"""
ASCII art banner display for Cyber_NetCAT.
"""

from netcat_tool import __version__, __author__
from netcat_tool.utils.colors import (
    Colors, _colorize, info, dim, bold, success, warning
)


BANNER = r"""
{c1} ██████╗██╗   ██╗██████╗ ███████╗██████╗      ███╗   ██╗███████╗████████╗ ██████╗ █████╗ ████████╗{r}
{c1}██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗     ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗╚══██╔══╝{r}
{c2}██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝     ██╔██╗ ██║█████╗     ██║   ██║     ███████║   ██║   {r}
{c2}██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗     ██║╚██╗██║██╔══╝     ██║   ██║     ██╔══██║   ██║   {r}
{c3}╚██████╗   ██║   ██████╔╝███████╗██║  ██║     ██║ ╚████║███████╗   ██║   ╚██████╗██║  ██║   ██║   {r}
{c3} ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝     ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝   ╚═╝   {r}
"""

TAGLINE = "Network Security Assessment Tool"

DISCLAIMER = (
    "This tool is for AUTHORIZED security testing and educational purposes ONLY.\n"
    "  Unauthorized access to computer systems is ILLEGAL. Use responsibly."
)


def print_banner():
    """Display the application banner with version and disclaimer."""
    formatted = BANNER.format(
        c1=Colors.BRIGHT_CYAN,
        c2=Colors.BRIGHT_BLUE,
        c3=Colors.BRIGHT_MAGENTA,
        r=Colors.RESET
    )
    print(formatted)

    # Info line
    version_str = f"v{__version__}"
    print(f"  {bold(TAGLINE)}  {dim('│')}  {info(version_str)}  {dim('│')}  {dim('by ' + __author__)}")
    print(f"  {dim('─' * 70)}")
    print(f"  {warning('⚠')}  {dim(DISCLAIMER)}")
    print(f"  {dim('─' * 70)}\n")


def print_module_banner(module_name, description=""):
    """
    Print a smaller banner for a specific module.

    Args:
        module_name: Name of the active module.
        description: Optional module description.
    """
    print(f"\n  {success('▶')} {bold(module_name.upper())}", end="")
    if description:
        print(f"  {dim('—')} {dim(description)}")
    else:
        print()
    print(f"  {dim('─' * 60)}")
