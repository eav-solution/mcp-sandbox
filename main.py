import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader

from mcp_sandbox.core.mcp_tools import SandboxToolsPlugin
from mcp_sandbox.api.routes import configure_app
from mcp_sandbox.api.auth_routes import router as auth_router
from mcp_sandbox.db.database import db
from mcp_sandbox.middleware.auth_middleware import AuthMiddleware
from mcp_sandbox.utils.config import logger, HOST, PORT, REQUIRE_AUTH


# API Key validation for SSE connections
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_api_key(request: Request = None, api_key_header: str = Depends(API_KEY_HEADER)):
    """Get API key from header or query parameters"""
    # First try to get from header
    if api_key_header:
        return api_key_header
    
    # Then try to get from query params if request is provided
    if request and "api_key" in request.query_params:
        return request.query_params.get("api_key")
    
    # No API key found
    return None

async def get_api_key_user(request: Request = None, api_key: str = Depends(get_api_key)):
    """Validate API key and get associated user"""
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key is required",
        )
    
    # Find user with provided API key
    for user in db.get_all_users():
        if user.get("api_key") == api_key:
            return user
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API Key",
    )

def main():
    """Main entry point for the application"""
    # Create FastAPI app
    app = FastAPI(title="MCP Sandbox")
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Adjust in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Add authentication middleware
    app.add_middleware(AuthMiddleware)

    # Include authentication routes
    app.include_router(auth_router)
    
    # Initialize sandbox tools
    sandbox_plugin = SandboxToolsPlugin()
    
    # Access the MCP server directly for configure_app
    # We pass the plugin itself so we can access its user context methods
    configure_app(app, sandbox_plugin)

    # Start FastAPI server
    auth_status = "enabled" if REQUIRE_AUTH else "disabled"
    logger.info(f"Starting MCP Sandbox with authentication {auth_status}")
    
    uvicorn.run(app, host=HOST, port=PORT)

if __name__ == "__main__":
    main() 