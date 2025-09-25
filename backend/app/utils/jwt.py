"""
JWT token utilities for authentication
"""
import jwt
from datetime import datetime, timedelta
from typing import Dict, Optional
import os
from cryptography.fernet import Fernet


class JWTManager:
    def __init__(self):
        self.secret_key = os.getenv("SECRET_KEY", "your-super-secret-key-here-change-in-production")
        self.algorithm = "HS256"
        self.access_token_expire_minutes = 60 * 24 * 7  # 7 days
        
        # For encrypting refresh tokens
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher_suite = Fernet(self.encryption_key)
    
    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key for refresh tokens"""
        key = os.getenv("ENCRYPTION_KEY")
        if key and len(key) == 44:  # Valid Fernet key length (base64 encoded 32 bytes)
            try:
                return key.encode()
            except:
                pass
        
        # Generate a new key (in production, this should be stored securely)
        new_key = Fernet.generate_key()
        print(f"WARNING: Generated new encryption key. In production, set ENCRYPTION_KEY to: {new_key.decode()}")
        return new_key
    
    def create_access_token(self, data: Dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({"exp": expire, "iat": datetime.utcnow()})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[Dict]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.JWTError:
            return None
    
    def encrypt_refresh_token(self, refresh_token: str) -> str:
        """Encrypt Google refresh token for storage"""
        return self.cipher_suite.encrypt(refresh_token.encode()).decode()
    
    def decrypt_refresh_token(self, encrypted_token: str) -> str:
        """Decrypt Google refresh token from storage"""
        return self.cipher_suite.decrypt(encrypted_token.encode()).decode()


# Global instance
jwt_manager = JWTManager()
