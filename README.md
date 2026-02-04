# Canvas API (GCP)

Student-focused Canvas-like API built with Flask and deployed to Google App Engine. Supports Auth0-based authentication, Google Cloud Datastore for core entities, and Cloud Storage for user avatars.

## Features
- Auth0-backed JWT authentication with per-route verification
- CRUD for users and courses with admin/instructor authorization
- Course enrollment management and avatar upload/download/delete via Cloud Storage
- Ready for App Engine standard (Python 3.9) deployment

## Prerequisites
- Python 3.9+
- Google Cloud project with App Engine enabled
- Auth0 tenant (domain, client ID/secret)
- Service account JSON with access to Datastore/Firestore (in Datastore mode) and Cloud Storage
- `gcloud` CLI installed and authenticated

## Environment
Provide the following variables (e.g., in a local `.env` file or App Engine env configuration):
- `PHOTO_BUCKET` – Cloud Storage bucket name for avatars
- `CLIENT_ID` – Auth0 client ID
- `CLIENT_SECRET` – Auth0 client secret
- `DOMAIN` – Auth0 domain (e.g., `your-tenant.us.auth0.com`)
- `ALGORITHMS` – JWT algorithm list (e.g., `RS256`)
- `SITE_URL` – Public base URL (e.g., `https://<project>.appspot.com`)
- `CLIENT_KEY` – Flask secret key

## Local Development
1) Install dependencies:
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```
2) Export environment variables (or create a `.env` with the values above).
3) Run the API:
```bash
python run.py
```
The service listens on http://127.0.0.1:8080.

## Deployment (App Engine)
1) Ensure `app.yaml` has the correct `runtime` and `service` values.
2) Deploy:
```bash
gcloud app deploy
```
3) Browse:
```bash
gcloud app browse
```

## Endpoints (high level)
- `POST /users/login` – exchange Auth0 credentials for a JWT
- `GET /decode` – decode/validate supplied JWT
- `GET /users` – list users (admin only)
- `GET /users/<user_id>` – fetch one user (self or admin)
- `POST|GET|DELETE /users/<user_id>/avatar` – upload/download/delete avatar (self)
- `POST|GET /courses` – create (admin) or list courses
- `GET|PATCH|DELETE /courses/<course_id>` – retrieve/update/delete a course (admin)
- `GET|PATCH /courses/<course_id>/students` – read/update enrollments (admin or instructor)

## Testing
- Manual: use the provided Postman collection in `tests/`
- Automated tests: not yet included; consider adding pytest + moto-style fakes for GCP

## Project Layout
- `app/` – Flask application (`main.py`, `routes.py`, `utils.py`)
- `config.py` – environment-driven configuration
- `run.py` – local entry point
- `app.yaml` – App Engine service definition
- `tests/` – Postman collections
