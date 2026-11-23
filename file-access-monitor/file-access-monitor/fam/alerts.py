"""Send alerts: console always, Telegram and e-mail if you set them up."""
import os
import smtplib
import sys
import threading
import time
import urllib.parse
import urllib.request
from email.message import EmailMessage

from .common import SEV

COLORS = {"low": "\033[36m", "medium": "\033[33m", "high": "\033[31m", "critical": "\033[1;37;41m"}
RESET = "\033[0m"


class AlertManager:
    def __init__(self, cfg):
        a = cfg.get("alerts", {})
        self.min_sev = SEV[a.get("min_notify_severity", "medium")]
        self.cooldown = a.get("cooldown_sec", 30)
        tg = a.get("telegram", {})
        # Secrets are better in environment variables than in the config file.
        self.tg_token = os.environ.get("FAM_TELEGRAM_TOKEN") or tg.get("bot_token", "")
        self.tg_chat = os.environ.get("FAM_TELEGRAM_CHAT") or tg.get("chat_id", "")
        self.email = a.get("email", {})
        self.last_sent = {}

    def notify(self, alert):
        if SEV.get(alert["severity"], 0) < self.min_sev:
            return
        key, now = (alert["rule"], alert["path"]), time.time()
        if now - self.last_sent.get(key, 0) < self.cooldown:      # same alert again too soon: stay quiet
            return
        self.last_sent[key] = now
        text = self._text(alert)
        self._console(alert, text)
        if self.tg_token and self.tg_chat:
            threading.Thread(target=self._telegram, args=(text,), daemon=True).start()
        if self.email.get("enabled"):
            threading.Thread(target=self._email, args=(alert, text), daemon=True).start()

    @staticmethod
    def _text(a):
        who = f" by {a['user']}" if a.get("user") else ""
        exe = f" via {a['exe']}" if a.get("exe") else ""
        mitre = f" [{a['mitre']}]" if a.get("mitre") else ""
        return f"{a['severity'].upper()} {a['rule']}: {a['message']}{who}{exe}{mitre}"

    @staticmethod
    def _console(a, text):
        color = COLORS.get(a["severity"], "") if sys.stdout.isatty() else ""
        print(f"{color}[ALERT] {text}{RESET if color else ''}", flush=True)

    def _telegram(self, text):
        try:
            data = urllib.parse.urlencode({"chat_id": self.tg_chat, "text": text}).encode()
            urllib.request.urlopen(f"https://api.telegram.org/bot{self.tg_token}/sendMessage", data, timeout=8)
        except Exception as e:
            print(f"[alerts] telegram failed: {e.__class__.__name__}")

    def _email(self, a, text):
        try:
            c = self.email
            msg = EmailMessage()
            msg["Subject"] = f"[FAM {a['severity']}] {a['rule']}"
            msg["From"], msg["To"] = c["user"], c["to"]
            msg.set_content(text)
            with smtplib.SMTP(c["smtp_host"], c.get("port", 587), timeout=10) as s:
                s.starttls()
                s.login(c["user"], os.environ.get("FAM_EMAIL_PASSWORD") or c.get("password", ""))
                s.send_message(msg)
        except Exception as e:
            print(f"[alerts] email failed: {e.__class__.__name__}")
