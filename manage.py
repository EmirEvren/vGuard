"""vGuard CLI management commands."""
import click
from app import create_app
from app.extensions import db


@click.group()
def cli():
    """vGuard management commands."""
    pass


@cli.command()
def init_db():
    """Initialize database and create all tables."""
    app = create_app()
    with app.app_context():
        db.create_all()
        click.echo("Database tables created successfully.")


@cli.command()
def seed():
    """Seed database with default users and rules."""
    app = create_app()
    with app.app_context():
        db.create_all()
        _seed_users()
        _seed_rules()
        click.echo("Database seeded successfully.")


@cli.command()
def migrate_json():
    """Migrate existing JSON data to SQLite database."""
    app = create_app()
    with app.app_context():
        db.create_all()
        from app.services.migration_service import migrate_all_json_data
        migrate_all_json_data()
        click.echo("JSON data migrated to database successfully.")


def _seed_users():
    """Create default users if none exist."""
    from app.models.user import User

    if User.query.count() > 0:
        click.echo("  Users already exist, skipping user seed.")
        return

    defaults = [
        ("admin", "admin@vguard.local", "Vg!2026-Secure#A1", "Admin"),
        ("analyst", "analyst@vguard.local", "Vg!2026-Analyze#B2", "Analyst"),
        ("viewer", "viewer@vguard.local", "Vg!2026-View#C3", "Viewer"),
    ]

    for username, email, password, role in defaults:
        user = User(
            username=username,
            email=email,
            role=role,
            company="vGuard Demo",
            created_by="System",
        )
        user.set_password(password)
        db.session.add(user)

    db.session.commit()
    click.echo(f"  Created {len(defaults)} default users.")


def _seed_rules():
    """Seed default detection rules if none exist."""
    from app.models.rule import Rule
    import json
    import os

    if Rule.query.count() > 0:
        click.echo("  Rules already exist, skipping rule seed.")
        return

    rules_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "vguard_rules.json"
    )
    if not os.path.exists(rules_file):
        click.echo("  No vguard_rules.json found, skipping rule seed.")
        return

    with open(rules_file, "r", encoding="utf-8") as f:
        rules_data = json.load(f)

    count = 0
    for category, patterns in rules_data.items():
        if not isinstance(patterns, list):
            continue
        for i, pattern in enumerate(patterns):
            rule = Rule(
                rule_id=f"{category.lower()}_{i+1:03d}",
                name=f"{category} Pattern {i+1}",
                category=category,
                pattern=pattern,
                severity="high" if "INJECTION" in category else "medium",
                action="DROP",
                enabled=True,
            )
            db.session.add(rule)
            count += 1

    db.session.commit()
    click.echo(f"  Loaded {count} detection rules from vguard_rules.json.")


if __name__ == "__main__":
    cli()
