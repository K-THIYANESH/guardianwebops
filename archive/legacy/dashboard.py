#!/usr/bin/env python3
"""
Guardian Swarm - Web Monitoring Dashboard Launcher
=====================================================
Starts the Flask server to launch the real-time security dashboard.
Access the UI via: http://127.0.0.1:5000/
"""

import os
import sys
import webbrowser
from guardian_swarm.utils.visual import configure_console_encoding
import terminal_ui

def print_banner():
    """Renders a stylized startup banner on the console terminal."""
    configure_console_encoding()
    
    # 2. Main Title Banner inside styled box
    terminal_ui.Box(width=75, style="cyan", box_type="double") \
        .add_line("  🛡️  GUARDIAN SWARM - Web Monitoring Dashboard") \
        .add_line("     Real-Time Telemetry & Trust Orchestration Interface") \
        .print()
    print()

    box = terminal_ui.Box(width=75, style="green")
    box.add_line("🚀 [green][bold]Web Monitoring Dashboard Service Started[/bold][/green]")
    box.add_separator()
    box.add_line("🔗 [white]Dashboard URL :[/white] [cyan][bold]http://127.0.0.1:5000/[/bold][/cyan]")
    box.add_line("👤 [white]Usage Mode    :[/white] Open in web browser to inspect agent telemetry.")
    box.add_line("🧠 [white]Features      :[/white] Real-time metrics grid, sandbox action playground,")
    box.add_line("                 tamper-evident verification, and live swarm simulations.")
    box.add_separator()
    box.add_line("👉 [yellow]Note: Press Ctrl+C in this terminal window to stop the server.[/yellow]")
    box.print()
    print()

if __name__ == "__main__":
    print_banner()
    
    # Enable quick browser opening helper
    try:
        webbrowser.open("http://127.0.0.1:5000/")
    except Exception:
        pass

    # Import and run the Flask application
    from guardian_swarm.web.server import app
    app.run(host='127.0.0.1', port=5000, debug=False)
