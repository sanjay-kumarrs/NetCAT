"""
ANSI Color and styling helpers for terminal output.
Provides consistent, cross-platform colored output for the CLI.
"""

import os
import sys


def _supports_color():
    """Check if the terminal supports ANSI color codes."""
    if os.name == 'nt':
        # Enable ANSI on Windows 10+
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return os.environ.get('ANSICON') is not None
    return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()


COLORS_ENABLED = _supports_color()


class Colors:
    """ANSI escape code constants."""
    # Reset
    RESET = '\033[0m'

    # Regular colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # Bright colors
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    STRIKETHROUGH = '\033[9m'

    # Background colors
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'


def _colorize(text, color_code):
    """Apply color code to text if colors are enabled."""
    if not COLORS_ENABLED:
        return str(text)
    return f"{color_code}{text}{Colors.RESET}"


# ─── Status output helpers ────────────────────────────────────────────
def success(text):
    """Green text for successful operations."""
    return _colorize(text, Colors.BRIGHT_GREEN)


def error(text):
    """Red text for errors."""
    return _colorize(text, Colors.BRIGHT_RED)


def warning(text):
    """Yellow text for warnings."""
    return _colorize(text, Colors.BRIGHT_YELLOW)


def info(text):
    """Cyan text for informational messages."""
    return _colorize(text, Colors.BRIGHT_CYAN)


def header(text):
    """Bold magenta text for section headers."""
    return _colorize(text, f"{Colors.BOLD}{Colors.BRIGHT_MAGENTA}")


def dim(text):
    """Dimmed text for secondary information."""
    return _colorize(text, Colors.DIM)


def bold(text):
    """Bold text for emphasis."""
    return _colorize(text, Colors.BOLD)


def critical(text):
    """Bold red text on background for critical alerts."""
    return _colorize(text, f"{Colors.BOLD}{Colors.BRIGHT_WHITE}{Colors.BG_RED}")


# ─── Structured output helpers ────────────────────────────────────────
def print_success(text):
    """Print a success message with [+] prefix."""
    print(f"  {success('[+]')} {text}")


def print_error(text):
    """Print an error message with [-] prefix."""
    print(f"  {error('[-]')} {text}")


def print_warning(text):
    """Print a warning message with [!] prefix."""
    print(f"  {warning('[!]')} {text}")


def print_info(text):
    """Print an info message with [*] prefix."""
    print(f"  {info('[*]')} {text}")


def print_status(text):
    """Print a status message with [~] prefix."""
    print(f"  {_colorize('[~]', Colors.BRIGHT_BLUE)} {text}")


def print_header(title, width=60):
    """Print a decorated section header."""
    line = "─" * width
    print(f"\n  {header(line)}")
    print(f"  {header('│')} {bold(title)}")
    print(f"  {header(line)}")


def print_sub_header(title):
    """Print a sub-section header."""
    print(f"\n  {info('──▶')} {bold(title)}")


def print_result(key, value, indent=4):
    """Print a key-value result pair."""
    spaces = " " * indent
    print(f"{spaces}{dim(key + ':')} {value}")


def print_table_header(columns, widths):
    """Print a formatted table header row."""
    header_line = "  "
    separator = "  "
    for col, width in zip(columns, widths):
        header_line += f"{bold(col):<{width + 10}}  "
        separator += f"{'─' * width}  "
    print(separator)
    print(header_line)
    print(separator)


def print_table_row(values, widths):
    """Print a formatted table row."""
    row = "  "
    for val, width in zip(values, widths):
        row += f"{str(val):<{width}}  "
    print(row)


def progress_bar(current, total, prefix="Progress", length=40):
    """Display a progress bar in the terminal."""
    percent = current / total if total > 0 else 0
    filled = int(length * percent)
    bar_fill = "█" * filled
    bar_empty = "░" * (length - filled)
    bar = f"{success(bar_fill)}{dim(bar_empty)}"
    sys.stdout.write(f"\r  {info(prefix)} [{bar}] {percent*100:.1f}% ({current}/{total})")
    sys.stdout.flush()
    if current >= total:
        print()
