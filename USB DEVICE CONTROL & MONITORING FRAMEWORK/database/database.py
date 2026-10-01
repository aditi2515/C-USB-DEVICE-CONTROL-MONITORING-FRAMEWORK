"""SQLAlchemy setup and database lifecycle helpers."""
from __future__ import annotations

from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


def init_database(app) -> None:
    """Configure SQLAlchemy and create tables for a local installation."""
    from config import DATABASE_PATH, ensure_directories

    ensure_directories()
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DATABASE_PATH.as_posix()}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)
    with app.app_context():
        from database import models  # noqa: F401

        db.create_all()
