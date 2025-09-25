"""
OAuth2 authentication with Google
"""
import os
import secrets
import json
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from urllib.parse import urlencode
from pathlib import Path

from fastapi import APIRouter, Request, Response, HTTPException, Depends, Cookie
from fastapi.responses import RedirectResponse
from google_auth_oauthlib.flow import Flow
from google.auth.transport import requests as google_requests
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import httpx
from dotenv import load_dotenv

# Load environment variables
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(dotenv_path=env_path)

from .schemas import UserProfile, AuthResponse, ClassroomInfo, UserSession, TokenData
from .utils.jwt import jwt_manager

# Router for auth endpoints
router = APIRouter(prefix="/auth", tags=["authentication"])

# OAuth2 configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

# OAuth2 configuration loaded successfully

# OAuth scopes - using full Google API scope URLs
SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email", 
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/classroom.courses.readonly",
    "https://www.googleapis.com/auth/classroom.coursework.me",
    "https://www.googleapis.com/auth/classroom.rosters.readonly",
    "https://www.googleapis.com/auth/calendar.events.readonly"
]

# In-memory storage for sessions (replace with DB in production)
user_sessions: Dict[str, UserSession] = {}
oauth_states: Dict[str, Dict] = {}


def create_oauth_flow(state: str = None) -> Flow:
    """Create Google OAuth2 flow"""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(
            status_code=500, 
            detail="Google OAuth credentials not configured"
        )
    
    client_config = {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [f"{BACKEND_URL}/auth/callback"]
        }
    }
    
    flow = Flow.from_client_config(client_config, scopes=SCOPES)
    flow.redirect_uri = f"{BACKEND_URL}/auth/callback"
    
    return flow


async def verify_classroom_access(credentials: Credentials) -> ClassroomInfo:
    """Verify user has access to Google Classroom"""
    try:
        service = build('classroom', 'v1', credentials=credentials)
        courses = service.courses().list(pageSize=10).execute()
        
        courses_list = courses.get('courses', [])
        return ClassroomInfo(
            has_classroom_access=True,
            courses_count=len(courses_list)
        )
    except Exception as e:
        return ClassroomInfo(
            has_classroom_access=False,
            error=str(e)
        )


def get_current_user(session_token: Optional[str] = Cookie(None, alias="session")) -> Optional[TokenData]:
    """Get current user from session cookie"""
    if not session_token:
        return None
    
    payload = jwt_manager.verify_token(session_token)
    if not payload:
        return None
    
    return TokenData(**payload)


@router.get("/login")
async def login(request: Request):
    """Initiate Google OAuth2 login flow"""
    try:
        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)
        
        # Store state with timestamp for validation
        oauth_states[state] = {
            "timestamp": datetime.utcnow(),
            "redirect_uri": f"{BACKEND_URL}/auth/callback"
        }
        
        # Create OAuth flow
        flow = create_oauth_flow()
        
        # Generate authorization URL
        authorization_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            state=state,
            prompt='consent'  # Force consent to get refresh token
        )
        
        return RedirectResponse(url=authorization_url)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to initiate login: {str(e)}")


@router.get("/callback")
async def callback(
    request: Request,
    response: Response,
    code: str,
    state: str,
    error: Optional[str] = None
):
    """Handle Google OAuth2 callback"""
    if error:
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")
    
    # Verify state parameter
    if state not in oauth_states:
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    
    # Check state timestamp (expire after 10 minutes)
    state_data = oauth_states[state]
    if datetime.utcnow() - state_data["timestamp"] > timedelta(minutes=10):
        del oauth_states[state]
        raise HTTPException(status_code=400, detail="State parameter expired")
    
    try:
        # Exchange code for tokens
        flow = create_oauth_flow()
        flow.fetch_token(code=code)
        
        credentials = flow.credentials
        
        # Get user profile
        user_info_service = build('oauth2', 'v2', credentials=credentials)
        user_info = user_info_service.userinfo().get().execute()
        
        user_profile = UserProfile(
            email=user_info["email"],
            name=user_info["name"],
            picture=user_info.get("picture"),
            given_name=user_info.get("given_name"),
            family_name=user_info.get("family_name")
        )
        
        # Verify classroom access
        classroom_info = await verify_classroom_access(credentials)
        if not classroom_info.has_classroom_access:
            raise HTTPException(
                status_code=403, 
                detail="User does not have access to Google Classroom"
            )
        
        # Store refresh token (encrypted) if available
        encrypted_refresh_token = None
        if credentials.refresh_token:
            encrypted_refresh_token = jwt_manager.encrypt_refresh_token(
                credentials.refresh_token
            )
        
        # Create user session
        user_session = UserSession(
            email=user_profile.email,
            name=user_profile.name,
            google_tokens=encrypted_refresh_token,
            created_at=datetime.utcnow(),
            last_accessed=datetime.utcnow(),
            roles=[]
        )
        
        # Store session in memory (replace with DB in production)
        user_sessions[user_profile.email] = user_session
        
        # Create JWT token
        token_data = {
            "email": user_profile.email,
            "name": user_profile.name,
            "roles": []
        }
        
        access_token = jwt_manager.create_access_token(token_data)
        
        # Set httpOnly cookie
        response.set_cookie(
            key="session",
            value=access_token,
            httponly=True,
            secure=os.getenv("ENVIRONMENT") == "production",
            samesite="lax",
            max_age=60 * 60 * 24 * 7,  # 7 days
            domain=None  # Will use the domain from BACKEND_URL
        )
        
        # Clean up state
        del oauth_states[state]
        
        # Redirect to frontend
        return RedirectResponse(url=f"{FRONTEND_URL}/dashboard")
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Authentication failed: {str(e)}")


@router.get("/logout")
async def logout(response: Response):
    """Logout user and clear session cookie"""
    response.delete_cookie(
        key="session",
        httponly=True,
        secure=os.getenv("ENVIRONMENT") == "production",
        samesite="lax"
    )
    
    return AuthResponse(
        success=True,
        message="Successfully logged out"
    )


@router.get("/me")
async def get_current_user_info(current_user: TokenData = Depends(get_current_user)):
    """Get current user information"""
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Get additional session data
    user_session = user_sessions.get(current_user.email)
    if user_session:
        user_session.last_accessed = datetime.utcnow()
    
    return {
        "email": current_user.email,
        "name": current_user.name,
        "roles": current_user.roles,
        "session_info": {
            "created_at": user_session.created_at if user_session else None,
            "last_accessed": user_session.last_accessed if user_session else None,
            "has_refresh_token": bool(user_session and user_session.google_tokens)
        }
    }


@router.get("/status")
async def auth_status(current_user: TokenData = Depends(get_current_user)):
    """Check authentication status"""
    return {
        "authenticated": current_user is not None,
        "user": {
            "email": current_user.email,
            "name": current_user.name,
            "roles": current_user.roles
        } if current_user else None
    }


@router.get("/debug")
async def debug_config():
    """Debug endpoint to check configuration"""
    return {
        "google_client_id_exists": bool(GOOGLE_CLIENT_ID),
        "google_client_secret_exists": bool(GOOGLE_CLIENT_SECRET),
        "backend_url": BACKEND_URL,
        "frontend_url": FRONTEND_URL,
        "scopes_count": len(SCOPES),
        "google_client_id_prefix": GOOGLE_CLIENT_ID[:20] + "..." if GOOGLE_CLIENT_ID else None
    }


# Helper function to get Google credentials for API calls
def get_google_credentials(email: str) -> Optional[Credentials]:
    """Get Google credentials for a user"""
    user_session = user_sessions.get(email)
    if not user_session or not user_session.google_tokens:
        return None
    
    try:
        refresh_token = jwt_manager.decrypt_refresh_token(user_session.google_tokens)
        
        credentials = Credentials(
            token=None,
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            scopes=SCOPES
        )
        
        # Refresh the token if needed
        credentials.refresh(google_requests.Request())
        return credentials
        
    except Exception as e:
        print(f"Error getting credentials for {email}: {e}")
        return None
