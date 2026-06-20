# Network Lab — Real-Time Suricata IDS Dashboard

A cybersecurity dashboard that monitors Suricata IDS logs in real time, sends Telegram notifications on threat detection, and visualizes alerts in a modern web interface.

## Architecture

```
Suricata (eve.json)
       │
       ▼
Python Backend (Socket.IO)
       │
       ├──► Telegram Bot (instant notification)
       │
       └──► React Dashboard (WebSocket)
```

## Features

- **Real-time alert streaming** — Tails Suricata's `eve.json` and captures new alerts instantly
- **Telegram notifications** — Sends a bot message on every new threat detection
- **Live dashboard** — Pushed to the browser via Socket.IO, no page refresh needed
- **Severity classification** — Color-coded HIGH / MEDIUM / LOW badges
- **Live stat cards** — Total, HIGH, MEDIUM, and LOW alert counts update in real time

## Setup

### Requirements

- Python 3.10+
- Node.js 18+
- Suricata (Windows or Linux)

### Backend

```bash
cd backend
python -m venv venv

# Windows
.\venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt
```

Create a `backend/.env` file:

```env
TELEGRAM_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
SURICATA_LOG_PATH=C:\Program Files\Suricata\log\eve.json
```

### Frontend

```bash
npm install
```

## Running

**Terminal 1 — Backend:**

```bash
cd backend
.\venv\Scripts\python suricata.py
```

**Terminal 2 — Frontend:**

```bash
npm run dev
```

Open `http://localhost:5173` in your browser.

## Project Structure

```
network_lab/
├── backend/
│   ├── suricata.py        # Python backend (Socket.IO + Telegram)
│   ├── requirements.txt   # Python dependencies
│   └── .env               # Secrets (not committed to git)
├── src/
│   ├── App.tsx            # Dashboard UI
│   └── App.css            # Dark theme styles
├── .gitignore
└── package.json
└── docs                   # Simulations
```

## Telegram Bot Setup

1. Talk to `@BotFather` on Telegram and use `/newbot` to create a bot
2. Add the token to `.env` as `TELEGRAM_TOKEN`
3. For your chat ID, message `@userinfobot` or send a message to your bot then visit `https://api.telegram.org/bot<TOKEN>/getUpdates`

## Notes

- Historical logs are not read on startup — only new alerts are monitored
- Only `event_type == "alert"` lines are processed; normal traffic logs such as DNS, HTTP, and flow events are filtered out
- Never commit your `.env` file
