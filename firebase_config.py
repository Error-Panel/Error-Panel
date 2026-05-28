import requests
import json

# Your web app's Firebase configuration provided by the user
FIREBASE_CONFIG = {
  "apiKey": "AIzaSyDpNaFzT9b1WiLf6ZslW9dMXfH4A-Tg2vs",
  "authDomain": "error-panel-default.firebaseapp.com",
  "databaseURL": "https://error-panel-default-rtdb.firebaseio.com",
  "projectId": "error-panel-default",
  "storageBucket": "error-panel-default.appspot.com",
  "messagingSenderId": "595766965334",
  "appId": "1:595766965334:web:a9ff04a67e29317559b7f7",
  "measurementId": "G-QZ8T2TWEPE"
}

DB_URL = FIREBASE_CONFIG["databaseURL"].rstrip('/')

class FirebaseDB:
    """Helper class to interact with Firebase Realtime Database via REST API."""
    
    @staticmethod
    def get_admin_credentials():
        try:
            response = requests.get(f"{DB_URL}/admin_config.json")
            if response.status_code == 200 and response.json():
                data = response.json()
                return {
                    "username": data.get("username", "Admin"),
                    "password": data.get("password", "Admin")
                }
        except Exception as e:
            print(f"Error fetching admin credentials: {e}")
        return {"username": "Admin", "password": "Admin"}

    @staticmethod
    def update_admin_credentials(username, password):
        try:
            url = f"{DB_URL}/admin_config.json"
            # Get existing configuration first to preserve session token if any
            response = requests.get(url)
            current_data = response.json() if response.status_code == 200 and response.json() else {}
            current_data["username"] = username
            current_data["password"] = password
            
            response = requests.put(url, json=current_data)
            return response.status_code == 200
        except Exception as e:
            print(f"Error updating admin credentials: {e}")
            return False

    @staticmethod
    def update_session_token(token):
        try:
            url = f"{DB_URL}/admin_config.json"
            response = requests.get(url)
            current_data = response.json() if response.status_code == 200 and response.json() else {}
            current_data["session_token"] = token
            
            response = requests.put(url, json=current_data)
            return response.status_code == 200
        except Exception as e:
            print(f"Error updating session token: {e}")
            return False

    @staticmethod
    def get_session_token():
        try:
            response = requests.get(f"{DB_URL}/admin_config/session_token.json")
            if response.status_code == 200 and response.json():
                return response.json()
        except Exception as e:
            print(f"Error getting session token: {e}")
        return None

    @staticmethod
    def create_device_log(log_data):
        try:
            url = f"{DB_URL}/device_logs.json"
            response = requests.post(url, json=log_data)
            return response.status_code == 200
        except Exception as e:
            print(f"Error creating device log: {e}")
            return False

    @staticmethod
    def list_device_logs():
        try:
            response = requests.get(f"{DB_URL}/device_logs.json")
            if response.status_code == 200 and response.json():
                return response.json()
        except Exception as e:
            print(f"Error listing device logs: {e}")
        return {}

    @staticmethod
    def clear_device_logs():
        try:
            url = f"{DB_URL}/device_logs.json"
            response = requests.delete(url)
            return response.status_code == 200
        except Exception as e:
            print(f"Error clearing device logs: {e}")
            return False

    @staticmethod
    def get_user_by_username(username):
        try:
            response = requests.get(f"{DB_URL}/users.json")
            if response.status_code != 200 or not response.json():
                return None
            
            users = response.json()
            for uid, user_data in users.items():
                if user_data.get('usuario') == username:
                    user_data['firebase_id'] = uid # Keep track of the key for updates
                    return user_data
        except Exception as e:
            print(f"Error getting user: {e}")
        return None

    @staticmethod
    def update_user(firebase_id, data):
        try:
            url = f"{DB_URL}/users/{firebase_id}.json"
            response = requests.patch(url, json=data)
            return response.status_code == 200
        except Exception as e:
            print(f"Error updating user: {e}")
            return False

    @staticmethod
    def delete_user(firebase_id):
        try:
            url = f"{DB_URL}/users/{firebase_id}.json"
            response = requests.delete(url)
            return response.status_code == 200
        except Exception as e:
            print(f"Error deleting user: {e}")
            return False

    @staticmethod
    def create_user(data):
        try:
            url = f"{DB_URL}/users.json"
            response = requests.post(url, json=data)
            return response.status_code == 200
        except Exception as e:
            print(f"Error creating user: {e}")
            return False

    @staticmethod
    def list_users():
        try:
            response = requests.get(f"{DB_URL}/users.json")
            return response.json() if response.status_code == 200 and response.json() else {}
        except Exception as e:
            print(f"Error listing users: {e}")
        return {}

