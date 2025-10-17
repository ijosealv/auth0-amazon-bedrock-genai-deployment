import os
import json
import time
from functools import wraps
from traceback import print_exc
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
import boto3
import requests
from os import environ as env
import uuid
from flask import Blueprint
import base64
from cryptography.fernet import Fernet


# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY", "REPLACE_WITH_YOUR_SECRET_KEY")
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"

prod_bp = Blueprint('prod', __name__, url_prefix='/prod')


# Configure Flask for API Gateway deployment with /prod base path
app.config['APPLICATION_ROOT'] = '/prod'

# Helper function to generate correct URLs for API Gateway
def api_url_for(endpoint, **values):
    """Generate URLs that work with API Gateway stage"""
    base_path = '/prod'
    if endpoint == 'index':
        return base_path + '/'
    elif endpoint == 'login':
        return base_path + '/login'
    elif endpoint == 'callback':
        return base_path + '/callback'
    elif endpoint == 'logout':
        return base_path + '/logout'
    else:
        # For other endpoints, use Flask's url_for and prepend base_path
        return base_path + url_for(endpoint, **values)

# Auth0 Configuration
AUTH0_CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
AUTH0_BASE_URL = f"https://{AUTH0_DOMAIN}"
AUTH0_CALLBACK_URL = os.getenv("AUTH0_CALLBACK_URL", "https://your-api-gateway-url/callback")

# AWS Configuration (Lambda provides region automatically)
AWS_DEFAULT_REGION = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "us-east-1"))

# Bedrock Configuration
BEDROCK_AGENT_ID = os.getenv("BEDROCK_AGENT_ID")
BEDROCK_AGENT_ALIAS_ID = os.getenv("BEDROCK_AGENT_ALIAS_ID")
BEDROCK_MODEL_ID = "anthropic.claude-3-haiku-20240307-v1:0"
SESSION_TABLE_NAME = os.getenv("SESSION_TABLE_NAME", "bedrock-sessions")

# Initialize AWS clients (Lambda execution role provides credentials)
# Lambda automatically sets AWS_REGION environment variable
dynamodb = boto3.resource('dynamodb', region_name=AWS_DEFAULT_REGION)
bedrock = boto3.client(
    service_name="bedrock-agent-runtime",
    region_name=AWS_DEFAULT_REGION
)

# Auth0 OAuth Configuration
oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=f'{AUTH0_BASE_URL}/oauth/token',
    authorize_url=f'{AUTH0_BASE_URL}/authorize',
    client_kwargs={
        'scope': 'openid profile email offline_access okta.users.read',
    },
    server_metadata_url=f'https://{AUTH0_DOMAIN}/.well-known/openid-configuration'
)

def requires_auth(f):
    """Decorator to require authentication for protected routes.
    Redirects to login if user is not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'profile' not in session:
            return redirect(api_url_for('login'))
        return f(*args, **kwargs)
    return decorated

# Encryption helper functions
def get_encryption_key():
    """Get encryption key from AWS Secrets Manager"""
    secret_name = os.getenv('TOKEN_ENCRYPTION_SECRET_NAME', 'token-encryption-key')
    
    try:
        secrets_client = boto3.client('secretsmanager')
        response = secrets_client.get_secret_value(SecretId=secret_name)
        
        # Parse the JSON response to get the key
        secret_data = json.loads(response['SecretString'])
        return secret_data['key']
    except Exception as e:
        print(f"Error getting encryption key: {e}")
        return None

def encrypt_token(token: str) -> str:
    """Encrypt token before storing in DynamoDB"""
    if not token:
        return None
    
    try:
        key = get_encryption_key()
        if not key:
            print("Warning: No encryption key available, storing token in plaintext")
            return token  # Fallback to plaintext if key unavailable
            
        f = Fernet(key.encode())
        encrypted = f.encrypt(token.encode())
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        print(f"Error encrypting token: {e}")
        return token  # Fallback to plaintext

def decrypt_token(encrypted_token: str) -> str:
    """Decrypt token after retrieving from DynamoDB"""
    if not encrypted_token:
        return None
    
    try:
        key = get_encryption_key()
        if not key:
            print("Warning: No encryption key available, assuming token is plaintext")
            return encrypted_token  # Assume it's already plaintext
            
        f = Fernet(key.encode())
        decoded = base64.b64decode(encrypted_token.encode())
        return f.decrypt(decoded).decode()
    except Exception as e:
        print(f"Error decrypting token (may be plaintext): {e}")
        return encrypted_token  # Assume it's plaintext

# DynamoDB helper functions
def store_session_data(session_id, refresh_token, federated_token, user_data):
    """Store session data in DynamoDB
    
    Args:
        session_id: Unique session identifier
        refresh_token: Auth0 refresh token
        federated_token: Federated access token
        user_data: User profile information
    """
    try:
        table = dynamodb.Table(SESSION_TABLE_NAME)
        # TTL: Session expires in 24 hours
        ttl = int(time.time()) + (24 * 60 * 60)
        
        # Encrypt tokens before storing
        encrypted_refresh = encrypt_token(refresh_token) if refresh_token else None
        encrypted_federated = encrypt_token(federated_token) if federated_token else None
        
        table.put_item(Item={
            'session_id': session_id,
            'refresh_token': encrypted_refresh,      # Now encrypted
            'federated_token': encrypted_federated,  # Now encrypted
            'user_id': user_data.get('user_id'),
            'user_email': user_data.get('email'),
            'user_name': user_data.get('name'),
            'user_picture': user_data.get('picture'),
            'ttl': ttl,
            'created_at': int(time.time())
        })
        print(f"Stored session data for session_id: {session_id}")
    except Exception as e:
        print(f"Error storing session data: {str(e)}")
        raise

def get_session_data(session_id):
    """Retrieve session data from DynamoDB
    
    Args:
        session_id: Session identifier
        
    Returns:
        Dict containing session data or None if not found
    """
    try:
        table = dynamodb.Table(SESSION_TABLE_NAME)
        response = table.get_item(Key={'session_id': session_id})
        item = response.get('Item')
        
        if item:
            # Remove TTL field from response
            item.pop('ttl', None)
            return item
        return None
    except Exception as e:
        print(f"Error retrieving session data for {session_id}: {str(e)}")
        return None

@app.route("/login")
def login():
    """Initiate Auth0 login flow.
    Clears existing session and redirects to Auth0 for authentication."""
    # Clear any existing session data before starting new auth flow
    session.clear()
    return auth0.authorize_redirect(
        redirect_uri=AUTH0_CALLBACK_URL,
        response_type='code'
    )

@app.route("/callback")
def callback():
    """Handle Auth0 callback after successful authentication.
    Stores user information and tokens in session."""
    try:
        # Get the token using the callback
        token = auth0.authorize_access_token()
        
        # Store the user info in session
        userinfo = auth0.get('userinfo').json()
        print(f"User info received: {userinfo}")
        
        user_profile = {
            'user_id': userinfo['sub'],
            'name': userinfo['name'],
            'email': userinfo['email'],
            'picture': userinfo['picture']
        }
        session['profile'] = user_profile
        
        # Generate a unique session ID for DynamoDB storage
        session_id = str(uuid.uuid4())
        session['session_id'] = session_id
        
        # Store the tokens
        session['user'] = token
        if "refresh_token" in token:
            session["refresh_token"] = token["refresh_token"]
            print("Stored refresh token in session")
        else:
            print("No refresh token received")
        
        # Get federated token from token vault
        federated_token = None
        try:
            federated_token = get_tokenset()
        except Exception as e:
            print(f"Warning: Could not get federated token: {str(e)}")
        
        # Store session data in DynamoDB
        store_session_data(
            session_id=session_id,
            refresh_token=token.get("refresh_token"),
            federated_token=federated_token,
            user_data=user_profile
        )
        
        return redirect(api_url_for('index'))
    except Exception as e:
        print(f"Error in callback: {str(e)}")
        session.clear()
        return redirect(api_url_for('login'))

@app.route("/logout")
def logout():
    """Handle user logout.
    Clears session and redirects to Auth0 logout endpoint."""
    print("Logging out inthe flak app ")
    session.clear()
    # Get the base URL from the request
    base_url = request.url_root.rstrip('/')
    return_url = f"{base_url}/"
    print(f"Redirecting to: {return_url}")
    print(f"Auth0 base URL: {AUTH0_BASE_URL}")
    return redirect(
        f"{AUTH0_BASE_URL}/v2/logout?returnTo={return_url}&client_id={AUTH0_CLIENT_ID}"
    )

@app.route("/")
@requires_auth
def index():
    """Main application page.
    Requires authentication and displays user information."""
    return render_template("index.html", user=session['profile'])

def get_completion_from_response(response):
    """Extract completion text from Bedrock response.
    
    Args:
        response: Bedrock agent response object
        
    Returns:
        str: Combined completion text
    """
    completion = ""
    for event in response.get("completion"):
        chunk = event["chunk"]
        completion += chunk["bytes"].decode()
    return completion

def get_tokenset():
    """Exchange refresh token for federated access token.
    
    Returns:
        str: Federated access token or None if exchange fails
    """
    if not session.get("refresh_token"):
        print("No refresh token available in session")
        return None
    
    url = f"https://{env.get('AUTH0_DOMAIN')}/oauth/token"
    headers = {"content-type": "application/json"}
    payload = {
        "client_id": env.get("AUTH0_CLIENT_ID"),
        "client_secret": env.get("AUTH0_CLIENT_SECRET"),
        "grant_type": "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token",
        "subject_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
        "subject_token": session["refresh_token"],
        "connection": env.get("AUTH0_CONNECTION_NAME"),
        "audience": f"https://{env.get('AUTH0_DOMAIN')}/api/v2/",
        "requested_token_type": "http://auth0.com/oauth/token-type/federated-connection-access-token",
        "scope": "okta.users.read okta.users.read.self"
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        tokenset = response.json()
        return tokenset.get("access_token")
    except requests.exceptions.RequestException as e:
        error_text = e.response.text if hasattr(e, 'response') else "No response"
        print("Error getting token:", error_text)
        return None

@app.route("/token-info", methods=["GET"])
@requires_auth
def token_info():
    """Get token information for display purposes"""
    try:
        print("Token info endpoint called")
        session_id = session.get('session_id')
        print(f"Session ID from Flask session: {session_id}")
        
        if not session_id:
            print("No session_id found in Flask session")
            return jsonify({'error': 'No session found', 'debug': 'session_id missing'}), 401
        
        # Get session data from DynamoDB
        print(f"Attempting to get session data for: {session_id}")
        session_data = get_session_data(session_id)
        print(f"Session data retrieved: {session_data is not None}")
        
        if not session_data:
            print("No session data found in DynamoDB")
            return jsonify({'error': 'Session data not found', 'debug': f'session_id: {session_id}'}), 404
        
        # Decrypt tokens for display (they're stored encrypted)
        encrypted_federated = session_data.get('federated_token')
        encrypted_refresh = session_data.get('refresh_token')
        
        print(f"Encrypted federated token exists: {encrypted_federated is not None}")
        print(f"Encrypted refresh token exists: {encrypted_refresh is not None}")
        
        decrypted_federated = decrypt_token(encrypted_federated) if encrypted_federated else 'Not available'
        decrypted_refresh = decrypt_token(encrypted_refresh) if encrypted_refresh else 'Not available'
        
        print(f"Decrypted federated token length: {len(decrypted_federated) if decrypted_federated != 'Not available' else 0}")
        print(f"Decrypted refresh token length: {len(decrypted_refresh) if decrypted_refresh != 'Not available' else 0}")
        
        # Parse JWT token to get actual expiration time
        token_expires_at = None
        expires_in = 86400  # Default 24 hours
        
        if decrypted_federated and decrypted_federated != 'Not available':
            try:
                import base64
                import json
                from datetime import datetime
                
                # Split JWT and get payload
                parts = decrypted_federated.split('.')
                if len(parts) >= 2:
                    payload = parts[1]
                    # Add padding if needed
                    payload += '=' * (4 - len(payload) % 4)
                    
                    decoded_payload = base64.b64decode(payload)
                    token_data = json.loads(decoded_payload)
                    
                    # Get expiration timestamp
                    exp_timestamp = token_data.get('exp')
                    if exp_timestamp:
                        token_expires_at = datetime.fromtimestamp(exp_timestamp).isoformat()
                        current_time = datetime.now()
                        exp_time = datetime.fromtimestamp(exp_timestamp)
                        expires_in = max(0, int((exp_time - current_time).total_seconds()))
                        
            except Exception as e:
                print(f"Error parsing JWT token: {e}")
        
        # Return token info (tokens decrypted for display)
        return jsonify({
            'session_id': session_id,
            'access_token': decrypted_federated,
            'refresh_token': decrypted_refresh,
            'user_id': session_data.get('user_id'),
            'expires_in': expires_in,
            'token_expires_at': token_expires_at,
            'storage_encrypted': True,
            'auth_provider': 'Auth0'
        })
        
    except Exception as e:
        print(f"Error getting token info: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Failed to retrieve token information', 'debug': str(e)}), 500

@app.route("/chat", methods=["POST"])
@requires_auth
def chat():
    """Handle chat requests with Bedrock agent.
    
    Expects:
        - JSON payload with 'message' field
        - User must be authenticated
        
    Returns:
        - JSON response with agent's response
        - Session ID and request ID for tracking
    """
    try:
        user_message = request.json.get("message", "")
        if not user_message:
            return jsonify({"response": "No message provided."}), 400
        
        # Get the session ID from Flask session
        session_id = session.get('session_id')
        if not session_id:
            return jsonify({"response": "No session ID found. Please log in again."}), 401
        
        # Verify the session exists in DynamoDB
        session_data = get_session_data(session_id)
        if not session_data:
            return jsonify({"response": "Session expired or invalid. Please log in again."}), 401
        
        print(f'Using session_id: {session_id}')
        
        # Prepare the session state with ONLY session_id and basic user info
        # No tokens are sent to Bedrock
        session_state = {
            "sessionAttributes": {
                "session_id": session_id,
                "logged_in_user": session['profile']['email'],
                "user_id": session['profile']['user_id']
            }
        }
        print('Session state (secure - no tokens):', session_state)
        print('BEDROCK_AGENT_ID',BEDROCK_AGENT_ID)        
        print('BEDROCK_AGENT_ALIAS_ID',BEDROCK_AGENT_ALIAS_ID)        

        print('user_message', user_message)

        # Invoke the Bedrock agent
        response = bedrock.invoke_agent(
            agentId=BEDROCK_AGENT_ID,
            agentAliasId=BEDROCK_AGENT_ALIAS_ID,
            sessionId=session_id,
            inputText=user_message,
            enableTrace=True,
            sessionState=session_state
        )
        
        # Log action trace information
        trace = response.get('trace', [])
        print('response get completion',response.get('completion'))
        # Process the response
        completion = []
        for event in response.get('completion', []):
            print('Event back in the response:', event)
            if 'chunk' in event:
                try:
                    print('tryyyyyyyyy1')    
                    chunk_bytes = event['chunk']['bytes']
                    chunk_str = chunk_bytes.decode('utf-8')
                    print('Chunk:', chunk_str)
                    completion.append(chunk_str)
                    print('tryyyyyyyyy2')    
                except json.JSONDecodeError as je:
                    print(f"JSON decode error in chunk: {je}")
                    print(f"Raw chunk string: {chunk_str}")
                except Exception as e:
                    print(f"Error processing chunk: {str(e)}")
            else:
                print('No chunk in event:')
        
        # Combine the chunks of the response
        full_response = ''.join(completion)
        print('Full response:', full_response)
        return jsonify({
            'response': full_response,
            'sessionId': session_id,
            'requestId': response.get('requestId')
        })
        
    except Exception as e:
        print(f"Error in chat endpoint: {str(e)}")
        print(f"Error type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"response": f"Error: {str(e)}"}), 500

# Register the blueprint
app.register_blueprint(prod_bp)

# Remove the if __name__ == "__main__" block for Lambda deployment
# The Lambda handler will import this app directly