from flask import Flask, jsonify
from google.cloud import datastore, storage
import json, os

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
from app.routes import api_routes

def create_app():
    """
    app initializer
    """

    #init default flask app
    app = Flask(__name__)

    #Load configurations
    app.config.from_object('config.Configs')
    app.secret_key = app.config['CLIENT_KEY'] #secret key


    # Register routeing endpoints
    app.register_blueprint(api_routes)

    #Google Cloud clients
    app.storage_client = storage.Client()
    app.datastore_client = datastore.Client()

    # Init OAuth
    oauth = OAuth(app)
    oauth.register(
        'auth0',
        client_id=app.config['CLIENT_ID'],
        client_secret=app.config['CLIENT_SECRET'],
        api_base_url=f"https://{app.config['DOMAIN']}",
        access_token_url=f"https://{app.config['DOMAIN']}/oauth/token",
        authorize_url=f"https://{app.config['DOMAIN']}/authorize",
        client_kwargs={'scope': 'openid profile email'},
    )



    #Error handleing
    class AuthError(Exception):
        def __init__(self, error, status_code):
            self.error = error
            self.status_code = status_code

    @app.errorhandler(AuthError)
    def handle_auth_error(ex):
        response = jsonify(ex.error)
        response.status_code = ex.status_code
        return response



    # Verify the JWT in the http requst
    def verify_jwt(request):
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization'].split()
            token = auth_header[1]
        else:
            raise AuthError({"code": "no auth header",
                                "description":
                                    "Authorization header is missing"}, 401)
        
        jsonurl = urlopen("https://"+ app.config['DOMAIN']+"/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read())
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.JWTError:
            raise AuthError({"Error": "Unauthorized"}, 401)
        if unverified_header["alg"] == "HS256":
            raise AuthError({"code": "invalid_header",
                            "Error": "Unauthorized",
                            "description":
                                "Invalid header. "
                                "Use an RS256 signed JWT Access Token"}, 401)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=app.config['ALGORITHMS'],
                    audience=app.config['CLIENT_ID'],
                    issuer="https://"+ app.config['DOMAIN']+"/"
                )
            except jwt.ExpiredSignatureError:
                raise AuthError({"code": "token_expired",
                                "description": "token is expired"}, 401)
            except jwt.JWTClaimsError:
                raise AuthError({"code": "invalid_claims",
                                "description":
                                    "incorrect claims,"
                                    " please check the audience and issuer"}, 401)
            except Exception:
                raise AuthError({"code": "invalid_header",
                                "description":
                                    "Unable to parse authentication"
                                    " token."}, 401)

            return payload
        else:
            raise AuthError({"code": "no_rsa_key",
                                "description":
                                    "No RSA key in JWKS"}, 401)



if __name__ == '__main__':
    app=create_app()
    app.run(host='127.0.0.1', port=8080, debug=True)