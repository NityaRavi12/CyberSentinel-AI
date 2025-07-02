"""
Security and Authentication for CyberSentinel AI - ATITA
"""

import jwt
import bcrypt
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from fastapi import HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, validator
from core.config import settings
from core.logging import get_logger

logger = get_logger("security")

# Security scheme
security = HTTPBearer()

class User(BaseModel):
    """User model"""
    id: str
    username: str
    email: str
    roles: List[str]
    is_active: bool = True
    created_at: datetime
    last_login: Optional[datetime] = None

class UserCreate(BaseModel):
    """User creation model"""
    username: str
    email: str
    password: str
    roles: List[str] = ["analyst"]
    
    @validator('username')
    def validate_username(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', v):
            raise ValueError('Username must be 3-20 characters, alphanumeric and underscore only')
        return v
    
    @validator('email')
    def validate_email(cls, v):
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', v):
            raise ValueError('Invalid email format')
        return v
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        return v

class UserLogin(BaseModel):
    """User login model"""
    username: str
    password: str

class Token(BaseModel):
    """Token model"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    roles: List[str]

class RateLimiter:
    """Simple rate limiter"""
    
    def __init__(self):
        self.requests: Dict[str, List[datetime]] = {}
        self.max_requests = 100  # requests per window
        self.window_seconds = 60  # 1 minute window
    
    def is_allowed(self, client_id: str) -> bool:
        """Check if request is allowed"""
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=self.window_seconds)
        
        if client_id not in self.requests:
            self.requests[client_id] = []
        
        # Remove old requests
        self.requests[client_id] = [
            req_time for req_time in self.requests[client_id]
            if req_time > window_start
        ]
        
        # Check if under limit
        if len(self.requests[client_id]) >= self.max_requests:
            return False
        
        # Add current request
        self.requests[client_id].append(now)
        return True

class SecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware for adding security headers"""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        
        return response

class AuthService:
    """Authentication service"""
    
    def __init__(self):
        self.secret_key = settings.secret_key
        self.algorithm = settings.jwt_algorithm
        self.access_token_expire_minutes = settings.access_token_expire_minutes
        self.rate_limiter = RateLimiter()
        
        # In-memory user store (replace with database in production)
        self.users: Dict[str, User] = {}
        self._create_default_users()
    
    def _create_default_users(self):
        """Create default users for development"""
        default_password = bcrypt.hashpw("Admin123!".encode(), bcrypt.gensalt())
        
        self.users["admin"] = User(
            id="admin",
            username="admin",
            email="admin@cybersentinel.ai",
            roles=["admin", "analyst", "manager"],
            created_at=datetime.utcnow()
        )
        
        self.users["analyst"] = User(
            id="analyst",
            username="analyst",
            email="analyst@cybersentinel.ai",
            roles=["analyst"],
            created_at=datetime.utcnow()
        )
        
        # Store hashed passwords separately
        self._password_hashes = {
            "admin": default_password,
            "analyst": default_password
        }
    
    def create_user(self, user_data: UserCreate) -> User:
        """Create a new user"""
        if user_data.username in self.users:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already exists"
            )
        
        # Hash password
        hashed_password = bcrypt.hashpw(
            user_data.password.encode(), 
            bcrypt.gensalt()
        )
        
        user = User(
            id=user_data.username,
            username=user_data.username,
            email=user_data.email,
            roles=user_data.roles,
            created_at=datetime.utcnow()
        )
        
        self.users[user_data.username] = user
        self._password_hashes[user_data.username] = hashed_password
        
        logger.info(f"Created user: {user_data.username}")
        return user
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username and password"""
        user = self.users.get(username)
        if not user or not user.is_active:
            return None
        
        stored_hash = self._password_hashes.get(username)
        if not stored_hash:
            return None
        
        if bcrypt.checkpw(password.encode(), stored_hash):
            # Update last login
            user.last_login = datetime.utcnow()
            return user
        
        return None
    
    def create_access_token(self, user: User) -> Token:
        """Create JWT access token"""
        expires_delta = timedelta(minutes=self.access_token_expire_minutes)
        expire = datetime.utcnow() + expires_delta
        
        to_encode = {
            "sub": user.id,
            "username": user.username,
            "email": user.email,
            "roles": user.roles,
            "exp": expire
        }
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        
        return Token(
            access_token=encoded_jwt,
            expires_in=self.access_token_expire_minutes * 60,
            user_id=user.id,
            roles=user.roles
        )
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token and return payload"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"JWT error: {e}")
            return None
    
    def get_current_user(self, credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
        """Get current user from token"""
        token = credentials.credentials
        payload = self.verify_token(token)
        
        if payload is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        user_id = payload.get("sub")
        if not isinstance(user_id, str):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = self.users.get(user_id)
        
        if user is None or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        return user
    
    def require_roles(self, required_roles: List[str]):
        """Decorator to require specific roles"""
        def role_checker(current_user: User = Depends(get_current_user)):
            user_roles = set(current_user.roles)
            required_roles_set = set(required_roles)
            
            if not user_roles.intersection(required_roles_set):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions"
                )
            
            return current_user
        
        return role_checker
    
    def check_rate_limit(self, client_id: str) -> bool:
        """Check rate limit for client"""
        return self.rate_limiter.is_allowed(client_id)

# Global auth service instance
auth_service = AuthService()

# Dependency functions
def get_current_user() -> User:
    """Get current user dependency"""
    return auth_service.get_current_user()

def require_admin():
    """Require admin role"""
    return auth_service.require_roles(["admin"])

def require_analyst():
    """Require analyst role"""
    return auth_service.require_roles(["analyst", "admin"])

def require_manager():
    """Require manager role"""
    return auth_service.require_roles(["manager", "admin"])

def validate_input(text: str) -> str:
    """Validate and sanitize input"""
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"\']', '', text)
    return sanitized.strip()

def validate_threat_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate threat data input"""
    validated = {}
    
    # Validate title
    if 'title' in data:
        validated['title'] = validate_input(str(data['title']))[:200]  # Limit length
    
    # Validate description
    if 'description' in data:
        validated['description'] = validate_input(str(data['description']))[:2000]
    
    # Validate source details
    if 'source_details' in data and isinstance(data['source_details'], dict):
        validated['source_details'] = {}
        for key, value in data['source_details'].items():
            validated['source_details'][key] = validate_input(str(value))
    
    return validated
