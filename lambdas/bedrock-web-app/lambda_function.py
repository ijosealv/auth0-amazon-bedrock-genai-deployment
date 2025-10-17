"""
AWS Lambda handler for Flask application.
This module provides the entry point for AWS Lambda to run the Flask app.
"""

import serverless_wsgi
from app import app

def lambda_handler(event, context):
    """
    AWS Lambda handler function.
    
    This function serves as the entry point for AWS Lambda and uses
    serverless-wsgi to adapt the Flask WSGI application for Lambda.
    
    Args:
        event: AWS Lambda event object containing request data
        context: AWS Lambda context object containing runtime information
        
    Returns:
        dict: HTTP response formatted for API Gateway
    """
    return serverless_wsgi.handle_request(app, event, context)