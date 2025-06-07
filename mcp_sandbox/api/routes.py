from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import Response
from mcp_sandbox.api.sandbox_file import router as sandbox_file_router
from mcp.server.sse import SseServerTransport

from mcp_sandbox.utils.config import logger
from mcp_sandbox.db.database import db

def configure_app(app: FastAPI, sandbox_plugin):
    """Configure FastAPI app with routes and middleware"""

    # Mount sandbox file access routes
    app.include_router(sandbox_file_router)

    # Get the MCP server from the plugin
    mcp_server = sandbox_plugin.mcp._mcp_server
    
    # Server-Sent Events (SSE) handling
    event_stream = SseServerTransport("/messages/")

    async def validate_api_key(request: Request):
        """Validate API key from request query parameters
        
        When authentication is disabled, returns default root user"""
        from mcp_sandbox.utils.config import REQUIRE_AUTH, DEFAULT_USER_ID
        
        # If authentication is disabled, create and return default root user
        if not REQUIRE_AUTH:
            return {
                "id": DEFAULT_USER_ID,
                "username": "root",
                "api_key": "disabled-auth-mode",
                "is_active": True
            }
            
        # When authentication is required, validate API key
        api_key = request.query_params.get("api_key")
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API Key is required",
            )
        
        # Find user with provided API key
        for user in db.get_all_users():
            if user.get("api_key") == api_key:
                return user
        
        # Invalid API key
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
        )

    async def handle_event_stream(request: Request) -> Response:
        """Handle Server-Sent Events (SSE) connections"""
        # Validate API key before proceeding
        user = await validate_api_key(request)
        
        # Set the user context for the sandbox plugin
        sandbox_plugin.set_user_context(user.get("id"))
        
        # Set up initialization options
        initialization_options = mcp_server.create_initialization_options()
        
        async with event_stream.connect_sse(
                request.scope,
                request.receive,
                request._send,  # noqa: SLF001
        ) as (read_stream, write_stream):
            await mcp_server.run(
                read_stream,
                write_stream,
                initialization_options,
            )

        # After the SSE connection is closed, return an empty response
        return Response()

    # Add SSE routes
    app.add_route("/sse", handle_event_stream)
    app.mount("/messages/", app=event_stream.handle_post_message)

    @app.get("/health")
    async def health_check():
        return {"status": "healthy"}

    # File access middleware
    @app.middleware("http")
    async def track_file_access(request: Request, call_next):
        """Middleware to track file access"""
        response = await call_next(request)
        
        if request.url.path.startswith("/static/"):
            file_name = request.url.path.split("/")[-1]
            if file_name:
                logger.info(f"File accessed: {file_name}")
        
        return response
    
    return event_stream 