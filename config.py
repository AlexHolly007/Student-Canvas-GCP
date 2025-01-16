import os
from dotenv import load_dotenv

load_dotenv()

class Configs:
    PHOTO_BUCKET = os.getenv('PHOTO_BUCKET')
    CLIENT_ID = os.getenv('CLIENT_ID')
    CLIENT_SECRET = os.getenv('CLIENT_SECRET')
    DOMAIN = os.getenv('DOMAIN')
    ALGORITHMS = os.getenv('ALGORITHMS')
    SITE_URL = os.getenv('SITE_URL')
    CLIENT_KEY = os.getenv('CLIENT_KEY')