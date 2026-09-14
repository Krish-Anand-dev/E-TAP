# PhishGuard // Full-Stack Deployment Guide

This guide details how to deploy both the **FastAPI backend** and **React (Vite) frontend** for production or demo environments.

---

## Architecture Overview

```
[ Browser / Analyst ]
         │
         ├───► HTTPS (Static Assets) ───► [ Vercel / Netlify / CDN ]
         │                                (React Vite Production Build)
         │
         └───► POST /analyze ──────────► [ Render / Railway / Cloud Web Service ]
               GET /health                (Python 3.11 + FastAPI + Uvicorn)
                                                 │
                                                 ├──► MongoDB Atlas (Persistent Cluster)
                                                 ├──► AbuseIPDB API
                                                 ├──► VirusTotal v3 API (Throttled 4/min)
                                                 └──► Google Gemini AI
```

---

## Pre-Deployment Preparation

### 1. MongoDB Atlas Network Whitelist
Cloud providers (Render, Railway, AWS) use dynamic outbound IP addresses.
1. Log in to [MongoDB Atlas](https://cloud.mongodb.com/).
2. Navigate to **Network Access** > **IP Access List**.
3. Click **Add IP Address** > select **Allow Access from Anywhere** (`0.0.0.0/0`).
4. Ensure your database user credentials in `MONGODB_URI` have read/write access to the `phishguard` database.

### 2. Environment Variables Checklist
Prepare these values from your `.env` file:
* `MONGODB_URI` (`mongodb+srv://...`)
* `ABUSEIPDB_API_KEY`
* `VIRUSTOTAL_API_KEY`
* `GEMINI_API_KEY`
* `THREAT_INTEL_LIVE=1`
* `ALLOWED_ORIGINS` (Frontend domain, e.g. `https://phishguard.vercel.app`)

---

## Option 1: Modern Cloud Deployment (Recommended)

### Step 1: Deploy Backend to Render.com (or Railway)

1. **Sign in to [Render.com](https://render.com/)** and click **New +** > **Web Service**.
2. **Connect your GitHub repository**.
3. Configure the service settings:
   * **Name**: `phishguard-backend`
   * **Region**: Choose closest to your target audience (e.g., Singapore, Frankfurt, Oregon).
   * **Root Directory**: `threat-email-platform/backend`
   * **Runtime**: `Python 3`
   * **Build Command**: `pip install -r requirements.txt`
   * **Start Command**: `uvicorn app:app --host 0.0.0.0 --port $PORT`
   * **Plan**: Free or Starter
4. Scroll down to **Environment Variables** and add:
   | Key | Value |
   | :--- | :--- |
   | `MONGODB_URI` | *Your MongoDB Atlas connection string* |
   | `ABUSEIPDB_API_KEY` | *Your AbuseIPDB API key* |
   | `VIRUSTOTAL_API_KEY`| *Your VirusTotal API key* |
   | `GEMINI_API_KEY` | *Your Google Gemini API key* |
   | `THREAT_INTEL_LIVE` | `1` |
   | `ALLOWED_ORIGINS` | `*` *(lock to your Vercel URL after frontend deploy)* |
5. Click **Create Web Service**.
6. Once deployed, verify in your browser:
   `https://phishguard-backend.onrender.com/health`
   Should return: `{"status": "ok"}`

---

### Step 2: Deploy Frontend to Vercel (or Netlify)

1. **Sign in to [Vercel.com](https://vercel.com/)** and click **Add New...** > **Project**.
2. **Import your GitHub repository**.
3. Configure the project:
   * **Framework Preset**: `Vite`
   * **Root Directory**: Click **Edit** and select `threat-email-platform/frontend`
   * **Build Command**: `npm run build`
   * **Output Directory**: `dist`
4. Expand **Environment Variables**:
   | Key | Value |
   | :--- | :--- |
   | `VITE_API_BASE_URL` | `https://phishguard-backend.onrender.com` *(your backend URL without trailing slash)* |
5. Click **Deploy**.
6. Within ~60 seconds, Vercel gives you an active production URL:
   `https://phishguard-xxxx.vercel.app`

---

### Step 3: Lock Down Production CORS
To finalize production security:
1. Return to **Render.com** > `phishguard-backend` > **Environment**.
2. Edit `ALLOWED_ORIGINS` to your exact Vercel URL:
   `ALLOWED_ORIGINS=https://phishguard-xxxx.vercel.app`
3. Click **Save Changes** (Render will re-deploy with CORS locked strictly to your frontend domain).

---

## Option 2: Unified Docker / Single-Server VPS Deployment

If you are running on an Ubuntu VPS (DigitalOcean Droplet, AWS EC2, or Linode) or want a self-contained container:

### 1. Dockerfile (Multi-stage)
Place this `Dockerfile` in `threat-email-platform/`:

```dockerfile
# Stage 1: Build React Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
# Build production bundle with relative API path
ENV VITE_API_BASE_URL=""
RUN npm run build

# Stage 2: Python Backend with Static Serving
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

WORKDIR /app/backend
EXPOSE 5000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000"]
```

### 2. Run Container
```bash
docker build -t phishguard:latest -f Dockerfile .
docker run -d \
  -p 5000:5000 \
  --env-file backend/.env \
  --name phishguard-app \
  phishguard:latest
```

---

## Option 3: Production Static Build Run (Local / Judge Machine)

To run in a hardened, demo-ready state on a local laptop without Vite development server risks:

1. **Build the production frontend bundle:**
   ```bash
   cd threat-email-platform/frontend
   npm run build
   ```
2. **Preview using Vite's static preview server (loopback only):**
   ```bash
   npm run preview -- --host 127.0.0.1 --port 5173
   ```
3. **Start the FastAPI backend:**
   ```bash
   cd threat-email-platform/backend
   python -m uvicorn app:app --port 5000
   ```
4. Access `http://127.0.0.1:5173`.

---

## Verification & Sanity Check

| Test | Method | Expected Result |
| :--- | :--- | :--- |
| **Backend Health** | `GET /health` | HTTP 200 `{"status": "ok"}` |
| **Database Connection** | Check backend startup logs | `[DB STATUS] MONGODB ATLAS CLUSTER (Cloud)` |
| **Email Analysis** | Upload sample `.eml` | Full multi-stage JSON report returned |
| **XSS Isolation** | View HTML preview tab | Sandboxed iframe isolation banner visible |
| **VT Throttle** | Analyze email with 5+ URLs | Rate-limited indicators marked `THROTTLED (VT 4/MIN)` |
