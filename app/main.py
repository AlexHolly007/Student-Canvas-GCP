from flask import Flask
from google.cloud import datastore, storage
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
