#!/usr/bin/env python3
"""
Run script for PoisonProof AI Flask Application
"""

import os
from app import create_app

if __name__ == '__main__':
    # Get environment from environment variable or default to development
    env = os.environ.get('FLASK_ENV', 'development')
    
    # Create the Flask application
    app = create_app(env)
    
    # Run the application
    if env == 'development':
        app.run(
            host='127.0.0.1',
            port=5000,
            debug=True,
            use_reloader=True
        )
    else:
        # Production settings
        app.run(
            host='0.0.0.0',
            port=int(os.environ.get('PORT', 5000)),
            debug=False
        )