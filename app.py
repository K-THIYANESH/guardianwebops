#!/usr/bin/env python3
"""Standalone launcher for the Guardian Swarm dashboard application."""

import sys

from dotenv import load_dotenv
load_dotenv()

from guardian_swarm.utils.paths import PROJECT_ROOT, ensure_project_paths

sys.path.insert(0, str(PROJECT_ROOT))
ensure_project_paths()

from guardian_swarm.web.server import app


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    app.run(host=host, port=port, debug=False)
