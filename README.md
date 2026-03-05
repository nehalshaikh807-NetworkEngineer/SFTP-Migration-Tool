# Croma - SFTP Migration Tool

Simple, production-ready internal web tool to migrate SFTP workloads from Oracle Linux (legacy source) to RHEL 9 (destination) using SSH-driven operations.

## Project Status

- Status: Active and usable for internal migration runs.
- Backend and frontend run locally (`:8001` API and `:8080` UI).
- Connectivity gate enforcement is enabled before migration execution.
- Source-side dependency auto-install is implemented for `rsync` and `sshpass` (when password auth is used).
- SSH service restart logic supports both `sshd` and `ssh` systemd units.

## Tech Stack

- Backend: Python 3, FastAPI, Uvicorn, Paramiko, Pydantic
- Frontend: HTML, CSS, Vanilla JavaScript (single-page UI)
- Transfer/Ops: SSH, SFTP, rsync
- Job execution: In-memory job store + background thread workers
- Runtime: Local backend API + static frontend server

## What It Does

- Runs independent connectivity checks for source and destination.
- Blocks migration unless both checks pass.
- Migrates SFTP users, groups, UID/GID, password hashes, SSH keys, data, and SFTP/sshd configuration.
- Applies SELinux adjustments and performs post-migration validation.
- Provides live migration status and logs in a single-page UI.

## API

- `POST /test/source`
- `POST /test/destination`
- `POST /migration/dry-run`
- `POST /migration/start`
- `GET /migration/{job_id}/status`
- `GET /migration/logs?job_id=<id>`
- `GET /migration/{job_id}/report`
- `GET /health`

## Project Layout

- `backend/app/main.py` - FastAPI app entry
- `backend/app/routers/api.py` - API routes
- `backend/app/services/ssh_client.py` - Paramiko SSH wrapper
- `backend/app/services/migration_service.py` - Migration workflow
- `backend/app/services/connectivity_gate.py` - Connectivity gate enforcement
- `backend/app/services/job_store.py` - In-memory jobs/logs
- `frontend/index.html` - Single-page UI
- `frontend/static/croma-logo.png` - Runtime logo asset
- `scripts/setup_assets.py` - Copies logo into static path

## Prerequisites

- Python 3.10+
- SSH access from tool host to both servers
- Source/destination account with root or passwordless sudo
- `rsync` on source and destination
- `sshpass` on source only if destination password-based rsync is used

## Setup

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\activate
pip install -r backend/requirements.txt
python scripts/setup_assets.py
```

## Run Locally

Backend:

```bash
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8001
```

Frontend:

```bash
cd frontend
python -m http.server 8080
```

Open UI: `http://127.0.0.1:8080`

## Security Notes

- Credentials are processed in request memory only.
- Secrets are masked in app logs.
- Temporary rsync key material is removed after transfer.
- Restrict backend access to internal admin networks.

## Author

- Ashok Kadam
