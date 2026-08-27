import pyfiglet
from rich.console import Console
from rich.text import Text

console = Console()

DARK_BLUE = "#3E5BAA"
BLUE = "#3B82F6"


def print_banner():
    un_lines = pyfiglet.figlet_format("UN", font="ansi_shadow").split("\n")
    block_lines = pyfiglet.figlet_format("BLOCK", font="ansi_shadow").split("\n")

    for un_line, block_line in zip(un_lines, block_lines):
        line = Text(un_line, style=f"bold {DARK_BLUE}")
        line.append(block_line, style=f"bold {BLUE}")
        console.print(line)

    console.print(f"   repo health agent — v0.1.0\n", style=BLUE)