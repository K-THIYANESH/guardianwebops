import sys
import time
import threading

def configure_console_encoding() -> None:
    """Use UTF-8 on stdout/stderr when possible (fixes Windows cp1252 emoji crashes)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            pass

def safe_print(*args, **kwargs) -> None:
    print(*args, **kwargs)

configure_console_encoding()

class Color:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    END = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    GRAY = "\033[90m"

def print_header(title: str, emoji: str = "🛡️"):
    print(f"\n=== {emoji} {title} ===")

def print_sub_header(title: str, emoji: str = "🔹"):
    print(f"\n--- {emoji} {title} ---")

class LoadingSpinner:
    def __init__(self, message="Processing"):
        self.message = message

    def start(self):
        pass

    def stop(self):
        pass
