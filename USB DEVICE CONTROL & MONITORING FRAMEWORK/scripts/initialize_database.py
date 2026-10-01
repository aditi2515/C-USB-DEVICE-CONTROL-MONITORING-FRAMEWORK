"""Initialize SQLite tables and safe default policies."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app
from database.database import db
from database.models import Policy

app = create_app()
with app.app_context():
    db.create_all()
    defaults = [
        ("Block unknown devices", "BLOCK_UNKNOWN", "true"),
        ("Detect executable transfers", "DETECT_EXECUTABLE", "true"),
        ("Large transfer threshold", "MAX_TRANSFER_SIZE", "524288000"),
        ("File count threshold", "MAX_FILES_PER_SESSION", "100"),
    ]
    for name, policy_type, value in defaults:
        if not Policy.query.filter_by(policy_type=policy_type).first():
            db.session.add(Policy(policy_name=name, policy_type=policy_type, value=value))
    db.session.commit()
    print("Database and default policies initialized successfully.")
