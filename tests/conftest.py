"""Pytest fixtures for vGuard testing."""
import pytest
from app import create_app
from app.extensions import db
from app.models.user import User


@pytest.fixture
def app():
    """Create testing application context."""
    app = create_app("testing")
    with app.app_context():
        db.create_all()

        # Seed admin user
        admin = User(
            username="admin",
            email="admin@test.local",
            role="Admin",
            company="Test Corp",
            created_by="System",
        )
        admin.set_password("SecurePass123!#")
        db.session.add(admin)
        db.session.commit()

        yield app

        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Test client."""
    return app.test_client()


@pytest.fixture
def auth_client(client):
    """Client with authenticated admin session."""
    client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "SecurePass123!#"},
    )
    return client
