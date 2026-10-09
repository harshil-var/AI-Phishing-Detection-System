# AI-Powered Phishing Detection and Prevention Platform

A complete, production-style AI-Powered Phishing Detection and Prevention Platform. 

## Features
- **Web Dashboard**: Manually enter URLs for security scans.
- **Browser Extension**: Automatically detect suspicious websites while browsing.
- **Machine Learning Analysis**: Classifies URLs into SAFE, SUSPICIOUS, or PHISHING.
- **Explainable AI**: Understand why a URL is flagged.
- **LLM Security Chatbot**: Get guidance on phishing, online scams, and account security.

## Technology Stack
- **Frontend**: React, Vite, Tailwind CSS
- **Backend**: FastAPI, Python, Scikit-Learn
- **Extension**: Manifest V3, JavaScript

## Setup Instructions

### Backend Setup
1. Navigate to the `backend/` directory.
2. Create and activate a virtual environment.
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Copy `.env.example` to `.env` and configure `GROQ_API_KEY`.
5. Run the FastAPI server:
   ```bash
   uvicorn app.main:app --reload
   ```

### Frontend Setup
1. Navigate to the `frontend/` directory.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run the Vite development server:
   ```bash
   npm run dev
   ```

### Extension Setup
1. Open Chromium-based browser (Chrome/Edge).
2. Go to `chrome://extensions/`.
3. Enable "Developer mode".
4. Click "Load unpacked" and select the `extension/` folder.

## Machine Learning
The model pipeline is located in `ml_training/`. To retrain:
1. Ensure dataset is downloaded to `Dataset/`.
2. Run `python ml_training/train.py`.
