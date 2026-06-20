import eventlet
eventlet.monkey_patch()

import json
import os
from dotenv import load_dotenv
import requests
import socketio

load_dotenv()

TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

sio = socketio.Server(cors_allowed_origins='*', async_mode='eventlet')
app = socketio.WSGIApp(sio)

@sio.event
def connect(sid, _environ):
    print(f"[BAĞLANDI] Client: {sid}")

@sio.event
def disconnect(sid):
    print(f"[AYRILDI] Client: {sid}")

def send_telegram_alert(alert_msg):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": alert_msg,
        "parse_mode": "Markdown"
    }
    try:
        requests.post(url, json=payload)
    except Exception as e:
        print(f"Telegram hatası: {e}")

def watch_eve_json(file_path):
    with open(file_path, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                eventlet.sleep(0.1)
                continue

            try:
                data = json.loads(line)
                if data.get("event_type") == "alert":
                    alert = data["alert"]
                    src_ip = data.get("src_ip")
                    dest_ip = data.get("dest_ip")
                    signature = alert.get("signature")

                    msg = f"🚨 *Suricata Alert!*\n⚠️ *Tehdit:* {signature}\n🌐 *Kaynak:* {src_ip} -> *Hedef:* {dest_ip}"

                    send_telegram_alert(msg)
                    sio.emit('new_alert', data)
                    print(f"[ALERT] {signature}")
            except Exception as e:
                print(f"Log okuma hatası: {e}")

def start_tail():
    log_path = os.environ.get("SURICATA_LOG_PATH", r"C:\Program Files\Suricata\log\eve.json")
    watch_eve_json(log_path)

if __name__ == '__main__':
    eventlet.spawn(start_tail)
    eventlet.wsgi.server(eventlet.listen(('0.0.0.0', 5000)), app)
