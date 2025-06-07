"""Authentication middleware for FastAPI application

This middleware enforces authentication for all protected routes based on the configuration.
It supports multiple authentication methods (bearer token and API key) and handles exceptions
for public routes like login, register, static files, and documentation.
"""

import re
from typing import List, Optional
from fastapi import Request, status
from fastapi.responses import JSONResponse
from jose import JWTError, jwt

from mcp_sandbox.utils.config import REQUIRE_AUTH, DEFAULT_USER_ID, logger
from mcp_sandbox.auth.utils import SECRET_KEY, ALGORITHM
from mcp_sandbox.db.database import db


class AuthMiddleware:
    """Authentication middleware that enforces auth for protected routes"""
    
    def __init__(
        self, 
        app,
        public_paths: List[str] = None,
        public_path_regexes: List[str] = None
    ):
        """Initialize auth middleware
        
        Args:
            app: FastAPI application
            public_paths: List of path prefixes that are exempt from authentication
            public_path_regexes: List of regex patterns for paths exempt from authentication
        """
        self.app = app
        self.public_paths = public_paths or [
            "/api/register",
            "/api/token",
            "/messages/",  # SSE endpoint
            "/docs",
            "/redoc",
            "/openapi.json",
            "/static/",
            "/favicon.ico",
        ]
        self.public_path_regexes = public_path_regexes or [
            r"^/$",  # Root path for frontend
            r"^/index\.html$",
            r"^/assets/.*",
            r"^/css/.*",
            r"^/js/.*",
            r"^/img/.*",
        ]
        self.compiled_regexes = [re.compile(pattern) for pattern in self.public_path_regexes]
        logger.info(f"Auth middleware initialized with requireAuth={REQUIRE_AUTH}")
    
    async def __call__(self, scope, receive, send) -> None:
        """Process each request through the middleware"""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)

        # Always allow OPTIONS requests for CORS
        if request.method == "OPTIONS":
            await self.app(scope, receive, send)
            return
            
        # Short-circuit if authentication is disabled in config
        if not REQUIRE_AUTH:
            # Add default user context for disabled auth
            request.state.user = {
                "id": DEFAULT_USER_ID,
                "username": "root",
                "is_active": True,
            }
            scope["state"] = request.state
            await self.app(scope, receive, send)
            return
            
        # Check if this is a public path that doesn't require authentication
        path = request.url.path
        
        # Skip auth for public paths
        if self._is_public_path(path):
            await self.app(scope, receive, send)
            return
            
        # Authenticate the request
        user = await self._authenticate_request(request)
        if user:
            request.state.user = user
            scope["state"] = request.state
            await self.app(scope, receive, send)
            return
        
        # Return 401 Unauthorized if authentication failed
        response = JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Authentication required"},
            headers={"WWW-Authenticate": "Bearer"},
        )
        await response(scope, receive, send)
        return
    
    def _is_public_path(self, path: str) -> bool:
        """Check if a path is public and doesn't require authentication
        
        Args:
            path: URL path to check
            
        Returns:
            True if path is public, False otherwise
        """
        # Check fixed public paths
        for public_path in self.public_paths:
            if path.startswith(public_path):
                return True
                
        # Check regex patterns
        for pattern in self.compiled_regexes:
            if pattern.match(path):
                return True
                
        return False
    
    async def _authenticate_request(self, request: Request) -> Optional[dict]:
        """Authenticate a request using various methods
        
        Tries authentication methods in this order:
        1. Bearer token from Authorization header
        2. API key from X-API-Key header
        3. API key from query parameter
        
        Args:
            request: The incoming request
            
        Returns:
            User dict if authenticated, None otherwise
        """
        # Try to get token from Authorization header
        authorization = request.headers.get("Authorization")
        if authorization and authorization.startswith("Bearer "):
            token = authorization.replace("Bearer ", "")
            user = await self._authenticate_jwt(token)
            if user:
                return user
        
        # Try to get API key from header
        api_key = request.headers.get("X-API-Key")
        if api_key:
            user = self._authenticate_api_key(api_key)
            if user:
                return user
        
        # Try to get API key from query params
        api_key_param = request.query_params.get("api_key")
        if api_key_param:
            user = self._authenticate_api_key(api_key_param)
            if user:
                return user
        
        # Authentication failed
        return None
    
    async def _authenticate_jwt(self, token: str) -> Optional[dict]:
        """Authenticate using JWT token
        
        Args:
            token: JWT token string
            
        Returns:
            User dict if token is valid, None otherwise
        """
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            if not username:
                return None
                
            # Get user from database
            user = db.get_user(username=username)
            if not user or not user.get("is_active"):
                return None
                
            return user
        except JWTError:
            return None
    
    def _authenticate_api_key(self, api_key: str) -> Optional[dict]:
        """Authenticate using API key
        
        Args:
            api_key: API key string
            
        Returns:
            User dict if API key is valid, None otherwise
        """
        user = db.get_user_by_api_key(api_key)
        if user and user.get("is_active", True):
            return user
        
        return None
