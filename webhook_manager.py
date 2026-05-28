import requests
from datetime import datetime

class WebhookManager:
    """Discord Webhook Manager ported from Funcoes.php."""
    
    # Default URL from Funcoes.php
    DEFAULT_URL = "https://discord.com/api/webhooks/1198256616135479336/XkD7OX20jhox13geCHDtw5j_R5iLYIkAOv5mQtYNdZTC-S-m31qcgQW55dB2hf9ICz5Y"

    @staticmethod
    def discord_log(username, ip, version, webhook_url=DEFAULT_URL):
        payload = {
            "username": "Error Panel | LOGS",
            "avatar_url": "",
            "tts": False,
            "embeds": [{
                "title": "ALERTA DE LOGIN",
                "type": "rich",
                "description": "VERSÃO TESTADA",
                "color": 854044, # hex 0d081c
                "footer": {
                    "text": f"Data e hora: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}"
                },
                "fields": [
                    {"name": "LOGIN", "value": username, "inline": False},
                    {"name": "IP", "value": ip, "inline": False},
                    {"name": "VERSÃO", "value": version, "inline": False}
                ]
            }]
        }
        try:
            requests.post(webhook_url, json=payload)
        except Exception as e:
            print(f"Webhook error: {e}")
