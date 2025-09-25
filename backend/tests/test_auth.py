"""
Tests for OAuth2 authentication flow
"""
import pytest
import os
from unittest.mock import Mock, patch, MagicMock
from fastapi.testclient import TestClient
from datetime import datetime, timedelta

# Set test environment variables before importing app
os.environ["GOOGLE_CLIENT_ID"] = "test-client-id"
os.environ["GOOGLE_CLIENT_SECRET"] = "test-client-secret"
os.environ["SECRET_KEY"] = "test-secret-key-for-testing"
os.environ["BACKEND_URL"] = "http://localhost:8000"
os.environ["FRONTEND_URL"] = "http://localhost:3000"

from app.main import app
from app.auth import oauth_states, user_sessions
from app.utils.jwt import jwt_manager


client = TestClient(app)


class TestOAuthFlow:
    """Test OAuth2 flow with Google"""
    
    def setup_method(self):
        """Setup for each test"""
        # Clear in-memory stores
        oauth_states.clear()
        user_sessions.clear()
    
    def test_login_endpoint_redirects_to_google(self):
        """Test that /auth/login redirects to Google OAuth"""
        response = client.get("/auth/login", follow_redirects=False)
        
        assert response.status_code == 307
        assert "accounts.google.com" in response.headers["location"]
        assert "oauth2/auth" in response.headers["location"]
        
        # Check that state was stored
        assert len(oauth_states) == 1
    
    def test_login_without_credentials_fails(self):
        """Test login fails without Google credentials"""
        # Temporarily remove credentials
        original_client_id = os.environ.get("GOOGLE_CLIENT_ID")
        del os.environ["GOOGLE_CLIENT_ID"]
        
        try:
            response = client.get("/auth/login")
            assert response.status_code == 500
            assert "Google OAuth credentials not configured" in response.json()["detail"]
        finally:
            # Restore credentials
            if original_client_id:
                os.environ["GOOGLE_CLIENT_ID"] = original_client_id
    
    @patch('app.auth.build')
    @patch('app.auth.Flow.from_client_config')
    def test_callback_success_flow(self, mock_flow_class, mock_build):
        """Test successful OAuth callback with mocked Google API calls"""
        # Setup mocks
        mock_flow = Mock()
        mock_flow_class.return_value = mock_flow
        
        # Mock credentials
        mock_credentials = Mock()
        mock_credentials.refresh_token = "test-refresh-token"
        mock_flow.credentials = mock_credentials
        
        # Mock user info service
        mock_userinfo_service = Mock()
        mock_userinfo = Mock()
        mock_userinfo.get.return_value.execute.return_value = {
            "email": "test@example.com",
            "name": "Test User",
            "picture": "https://example.com/photo.jpg",
            "given_name": "Test",
            "family_name": "User"
        }
        mock_userinfo_service.userinfo.return_value = mock_userinfo
        
        # Mock classroom service
        mock_classroom_service = Mock()
        mock_courses = Mock()
        mock_courses.list.return_value.execute.return_value = {
            "courses": [{"id": "course1"}, {"id": "course2"}]
        }
        mock_classroom_service.courses.return_value = mock_courses
        
        # Configure build mock to return appropriate services
        def build_side_effect(service_name, version, credentials):
            if service_name == 'oauth2':
                return mock_userinfo_service
            elif service_name == 'classroom':
                return mock_classroom_service
            return Mock()
        
        mock_build.side_effect = build_side_effect
        
        # Create a valid state
        state = "test-state"
        oauth_states[state] = {
            "timestamp": datetime.utcnow(),
            "redirect_uri": "http://localhost:8000/auth/callback"
        }
        
        # Test callback
        response = client.get(
            f"/auth/callback?code=test-code&state={state}",
            follow_redirects=False
        )
        
        assert response.status_code == 307
        assert response.headers["location"] == "http://localhost:3000/dashboard"
        
        # Check that session cookie was set
        assert "session" in response.cookies
        
        # Verify user session was created
        assert "test@example.com" in user_sessions
        user_session = user_sessions["test@example.com"]
        assert user_session.email == "test@example.com"
        assert user_session.name == "Test User"
        assert user_session.google_tokens is not None  # Should be encrypted
        
        # Verify state was cleaned up
        assert state not in oauth_states
    
    def test_callback_with_invalid_state(self):
        """Test callback with invalid state parameter"""
        response = client.get("/auth/callback?code=test-code&state=invalid-state")
        
        assert response.status_code == 400
        assert "Invalid state parameter" in response.json()["detail"]
    
    def test_callback_with_expired_state(self):
        """Test callback with expired state parameter"""
        state = "expired-state"
        oauth_states[state] = {
            "timestamp": datetime.utcnow() - timedelta(minutes=15),  # Expired
            "redirect_uri": "http://localhost:8000/auth/callback"
        }
        
        response = client.get(f"/auth/callback?code=test-code&state={state}")
        
        assert response.status_code == 400
        assert "State parameter expired" in response.json()["detail"]
        assert state not in oauth_states  # Should be cleaned up
    
    def test_callback_with_oauth_error(self):
        """Test callback with OAuth error"""
        response = client.get("/auth/callback?error=access_denied&state=test")
        
        assert response.status_code == 400
        assert "OAuth error: access_denied" in response.json()["detail"]
    
    @patch('app.auth.build')
    @patch('app.auth.Flow.from_client_config')
    def test_callback_without_classroom_access(self, mock_flow_class, mock_build):
        """Test callback when user doesn't have classroom access"""
        # Setup mocks
        mock_flow = Mock()
        mock_flow_class.return_value = mock_flow
        mock_credentials = Mock()
        mock_flow.credentials = mock_credentials
        
        # Mock user info service
        mock_userinfo_service = Mock()
        mock_userinfo = Mock()
        mock_userinfo.get.return_value.execute.return_value = {
            "email": "test@example.com",
            "name": "Test User"
        }
        mock_userinfo_service.userinfo.return_value = mock_userinfo
        
        # Mock classroom service to raise exception (no access)
        mock_classroom_service = Mock()
        mock_classroom_service.courses.return_value.list.return_value.execute.side_effect = Exception("Access denied")
        
        def build_side_effect(service_name, version, credentials):
            if service_name == 'oauth2':
                return mock_userinfo_service
            elif service_name == 'classroom':
                return mock_classroom_service
            return Mock()
        
        mock_build.side_effect = build_side_effect
        
        # Create a valid state
        state = "test-state"
        oauth_states[state] = {
            "timestamp": datetime.utcnow(),
            "redirect_uri": "http://localhost:8000/auth/callback"
        }
        
        response = client.get(f"/auth/callback?code=test-code&state={state}")
        
        assert response.status_code == 403
        assert "does not have access to Google Classroom" in response.json()["detail"]
    
    def test_logout_clears_cookie(self):
        """Test logout endpoint clears session cookie"""
        response = client.get("/auth/logout")
        
        assert response.status_code == 200
        assert response.json()["success"] is True
        assert response.json()["message"] == "Successfully logged out"
        
        # Check that cookie is cleared (set to expire)
        set_cookie = response.headers.get("set-cookie", "")
        assert "session=" in set_cookie
        assert "Max-Age=0" in set_cookie or "expires=" in set_cookie
    
    def test_me_endpoint_without_auth(self):
        """Test /auth/me without authentication"""
        response = client.get("/auth/me")
        
        assert response.status_code == 401
        assert "Not authenticated" in response.json()["detail"]
    
    def test_me_endpoint_with_valid_token(self):
        """Test /auth/me with valid session token"""
        # Create a test user session
        test_email = "test@example.com"
        user_sessions[test_email] = Mock()
        user_sessions[test_email].created_at = datetime.utcnow()
        user_sessions[test_email].last_accessed = datetime.utcnow()
        user_sessions[test_email].google_tokens = "encrypted-token"
        
        # Create a valid JWT token
        token_data = {
            "email": test_email,
            "name": "Test User",
            "roles": []
        }
        token = jwt_manager.create_access_token(token_data)
        
        # Make request with session cookie
        response = client.get("/auth/me", cookies={"session": token})
        
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == test_email
        assert data["name"] == "Test User"
        assert data["roles"] == []
        assert "session_info" in data
        assert data["session_info"]["has_refresh_token"] is True
    
    def test_status_endpoint_authenticated(self):
        """Test /auth/status with authentication"""
        # Create a valid JWT token
        token_data = {
            "email": "test@example.com",
            "name": "Test User",
            "roles": ["user"]
        }
        token = jwt_manager.create_access_token(token_data)
        
        response = client.get("/auth/status", cookies={"session": token})
        
        assert response.status_code == 200
        data = response.json()
        assert data["authenticated"] is True
        assert data["user"]["email"] == "test@example.com"
        assert data["user"]["name"] == "Test User"
        assert data["user"]["roles"] == ["user"]
    
    def test_status_endpoint_unauthenticated(self):
        """Test /auth/status without authentication"""
        response = client.get("/auth/status")
        
        assert response.status_code == 200
        data = response.json()
        assert data["authenticated"] is False
        assert data["user"] is None


class TestJWTManager:
    """Test JWT token management"""
    
    def test_create_and_verify_token(self):
        """Test creating and verifying JWT tokens"""
        data = {"email": "test@example.com", "name": "Test User", "roles": []}
        token = jwt_manager.create_access_token(data)
        
        assert token is not None
        assert isinstance(token, str)
        
        # Verify token
        payload = jwt_manager.verify_token(token)
        assert payload is not None
        assert payload["email"] == "test@example.com"
        assert payload["name"] == "Test User"
        assert "exp" in payload
        assert "iat" in payload
    
    def test_verify_invalid_token(self):
        """Test verifying invalid token"""
        payload = jwt_manager.verify_token("invalid-token")
        assert payload is None
    
    def test_encrypt_decrypt_refresh_token(self):
        """Test encrypting and decrypting refresh tokens"""
        original_token = "test-refresh-token-12345"
        
        encrypted = jwt_manager.encrypt_refresh_token(original_token)
        assert encrypted != original_token
        assert isinstance(encrypted, str)
        
        decrypted = jwt_manager.decrypt_refresh_token(encrypted)
        assert decrypted == original_token


if __name__ == "__main__":
    pytest.main([__file__])
