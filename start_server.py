#!/usr/bin/env python3
"""
Startup script for the Port Scanner API server.
"""

import argparse
import logging
import sys
import os

# Add the backend directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.database import init_db_sync


def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def main():
    parser = argparse.ArgumentParser(description='Port Scanner API Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind to (default: 8000)')
    parser.add_argument('--reload', action='store_true', help='Enable auto-reload for development')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--init-db', action='store_true', help='Initialize database and exit')
    
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    # Initialize database
    logger.info("Initializing database...")
    init_db_sync()
    logger.info("Database initialized")
    
    if args.init_db:
        print("Database initialized successfully.")
        return
    
    # Import and run the server
    logger.info(f"Starting server on {args.host}:{args.port}")
    
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="debug" if args.verbose else "info"
    )


if __name__ == "__main__":
    main()
