"""Generate a report from the local SQLite database."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app
from core.report_generator import generate_report

parser = argparse.ArgumentParser(description="Generate a USB security report")
parser.add_argument("--format", choices=("json", "html", "csv"), default="json")
args = parser.parse_args()

app = create_app()
with app.app_context():
    print(generate_report(args.format))
