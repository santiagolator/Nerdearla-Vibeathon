"""
Pydantic schemas for OAuth and user data
"""
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Any
from datetime import datetime


class UserProfile(BaseModel):
    """User profile from Google OAuth"""
    email: EmailStr
    name: str
    picture: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None


class TokenData(BaseModel):
    """JWT token payload data"""
    email: EmailStr
    name: str
    roles: List[str] = []
    exp: Optional[datetime] = None
    iat: Optional[datetime] = None


class GoogleTokens(BaseModel):
    """Google OAuth tokens"""
    access_token: str
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    token_uri: str
    client_id: str
    client_secret: str
    scopes: List[str]


class AuthResponse(BaseModel):
    """Authentication response"""
    success: bool
    message: str
    user: Optional[UserProfile] = None


class ClassroomInfo(BaseModel):
    """Classroom verification info"""
    has_classroom_access: bool
    courses_count: Optional[int] = None
    error: Optional[str] = None


class UserSession(BaseModel):
    """User session data stored in memory/DB"""
    email: EmailStr
    name: str
    google_tokens: Optional[str] = None  # Encrypted refresh token
    created_at: datetime
    last_accessed: datetime
    roles: List[str] = []


class OAuthState(BaseModel):
    """OAuth state parameter for security"""
    state: str
    redirect_uri: str
    timestamp: datetime
