import os
import base64
import json
from datetime import datetime
from functools import wraps
from flask import Flask, request, abort, render_template, redirect, url_for, session

# Import components
from firebase_config import FirebaseDB
from crypto_manager import CryptoManager
from webhook_manager import WebhookManager

app = Flask(__name__)
app.secret_key = os.urandom(24) # Random secret for session management

# Base directory for absolute paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PRIVATE_KEY_PATH = os.path.join(BASE_DIR, "Keys", "PrivateKey.prk")

# Initialize Crypto Manager
if os.path.exists(PRIVATE_KEY_PATH):
    crypto = CryptoManager(PRIVATE_KEY_PATH)
else:
    crypto = None
    print(f"CRITICAL: Private key not found at {PRIVATE_KEY_PATH}")

def token_response(data):
    """Generates the encrypted and signed response expected by the client."""
    if not crypto: return "Error"
    json_data = json.dumps(data)
    data_hash = crypto.sha256(json_data)
    
    ack_token = {
        "Data": crypto.profile_encrypt(json_data, data_hash),
        "Sign": crypto.sign_by_private(json_data),
        "Hash": data_hash
    }
    return base64.b64encode(json.dumps(ack_token).encode()).decode()

# --- HELPER FOR DEVICE INFO ---
def extract_phone_info(user_agent):
    if not user_agent:
        return "Unknown Device"
    import re
    try:
        parenthesis_content = re.findall(r'\((.*?)\)', user_agent)
        if parenthesis_content:
            parts = [p.strip() for p in parenthesis_content[0].split(';')]
            android_version = None
            device_model = None
            for part in parts:
                if "Android" in part:
                    android_version = part.strip()
                elif "Build/" in part:
                    device_model = part.split("Build/")[0].strip()
                elif "iPhone" in part or "iPad" in part or "Macintosh" in part:
                    return part.strip()
            if android_version and device_model:
                return f"{device_model} ({android_version})"
            elif android_version:
                possible_model = parts[-1] if len(parts) > 1 else ""
                if possible_model and "Build" not in possible_model and "Android" not in possible_model:
                    return f"{possible_model} ({android_version})"
                return f"Android Device ({android_version})"
            return parts[-1] if parts else "Unknown Device"
    except Exception:
        pass
    if len(user_agent) > 50:
        return user_agent[:47] + "..."
    return user_agent

# --- AUTHENTICATION ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or 'admin_session_token' not in session:
            return redirect(url_for('login'))
        
        # Verify active session token against database to enforce single-session control
        db_token = FirebaseDB.get_session_token()
        if not db_token or session.get('admin_session_token') != db_token:
            session.clear()
            return redirect(url_for('login', error="Session Expired: Logged in from another device/browser."))
        return f(*args, **kwargs)
    return decorated_function

# --- WEB PANEL ROUTES ---

@app.route('/')
def home():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = request.args.get('error')
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        admin_creds = FirebaseDB.get_admin_credentials()
        if username == admin_creds.get('username') and password == admin_creds.get('password'):
            import uuid
            session_token = str(uuid.uuid4())
            session['logged_in'] = True
            session['admin_user'] = username
            session['admin_session_token'] = session_token
            # Write token to DB to invalidate previous logins
            FirebaseDB.update_session_token(session_token)
            return redirect(url_for('dashboard'))
          
        error = "Invalid Username or Password! Access Denied."
    return render_template('login.html', error=error)

@app.route('/dashboard')
@login_required
def dashboard():
    admin_creds = FirebaseDB.get_admin_credentials()
    user = {
        "usuario": admin_creds.get('username', 'Admin'),
        "tipo": "1",
        "expiracao": "Never Expires",
        "status": "1",
        "UID": "000000000000000",
        "version": "System Master"
    }
    return render_template('dashboard.html', user=user)

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        days = int(request.form.get('days', 30))
        version = request.form.get('version', 'v1')
        user_type = request.form.get('type', '3')
        custom_expire = request.form.get('custom_expire')

        if custom_expire:
            # Convert datetime-local format (YYYY-MM-DDTHH:MM) to Firebase (YYYY-MM-DD HH:MM:SS)
            dt = datetime.strptime(custom_expire, "%Y-%m-%dT%H:%M")
            expiracao_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        else:
            from datetime import timedelta
            dt_expire = datetime.now() + timedelta(days=days)
            expiracao_str = dt_expire.strftime("%Y-%m-%d %H:%M:%S")

        new_user = {
            "usuario": username,
            "senha": password,
            "expiracao": expiracao_str,
            "status": "1",
            "tipo": user_type,
            "UID": "000000000000000",
            "version": version,
            "CID": "1"
        }

        FirebaseDB.create_user(new_user)
        return redirect(url_for('users_list'))

    return render_template('add_user.html')

@app.route('/users_list')
@login_required
def users_list():
    users = FirebaseDB.list_users()
    return render_template('users_list.html', users=users)

@app.route('/reset_device/<fid>')
@login_required
def reset_device(fid):
    FirebaseDB.update_user(fid, {"UID": "000000000000000"})
    return redirect(url_for('users_list'))

@app.route('/delete_user/<fid>')
@login_required
def delete_user(fid):
    FirebaseDB.delete_user(fid)
    return redirect(url_for('users_list'))

@app.route('/admin_settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    message = None
    error = None
    admin_creds = FirebaseDB.get_admin_credentials()
    if request.method == 'POST':
        new_username = request.form.get('username', '').strip()
        new_password = request.form.get('password', '').strip()
        
        if not new_username or not new_password:
            error = "Username and Password cannot be empty!"
        else:
            success = FirebaseDB.update_admin_credentials(new_username, new_password)
            if success:
                admin_creds = {"username": new_username, "password": new_password}
                session['admin_user'] = new_username
                message = "Admin credentials updated successfully!"
            else:
                error = "Failed to update admin credentials."
    return render_template('admin_settings.html', admin=admin_creds, message=message, error=error)

@app.route('/device_logs')
@login_required
def device_logs():
    logs = FirebaseDB.list_device_logs()
    sorted_logs = []
    if logs:
        for log_id, log in logs.items():
            log['id'] = log_id
            sorted_logs.append(log)
        try:
            sorted_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        except Exception:
            pass
    return render_template('device_logs.html', logs=sorted_logs)

@app.route('/device_logs/clear')
@login_required
def clear_device_logs():
    FirebaseDB.clear_device_logs()
    return redirect(url_for('device_logs'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- API ROUTES (FOR THE MOD/CLIENT) ---

@app.route('/api/login', methods=['GET', 'POST'])
def api_login():
    if not crypto:
        return "Internal Server Error: Crypto not initialized", 500

    user_agent = request.headers.get('User-Agent', '')
    phone_info = extract_phone_info(user_agent)
    client_ip = request.remote_addr

    # Handle Legacy GET requests from the loader
    if request.method == 'GET':
        username = request.args.get('user')
        password = request.args.get('pass')
        device_uid = request.args.get('uid')

        if not username or not password:
            return "Parâmetros inválidos!", 400

        user = FirebaseDB.get_user_by_username(username)
        
        # Log validation check helper
        def log_attempt(status):
            FirebaseDB.create_device_log({
                "username": username,
                "device_uid": device_uid or "Unknown",
                "ip": client_ip,
                "user_agent": user_agent,
                "phone_info": phone_info,
                "status": status,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

        if not user or user.get('senha') != password:
            log_attempt("FAILED: Invalid Credentials")
            return "Login inválido!", 401

        if user.get('status') == "0":
            log_attempt("FAILED: Banned User")
            return "Banido!", 403

        dt_now = datetime.now()
        try:
            dt_expire = datetime.strptime(user.get('expiracao'), "%Y-%m-%d %H:%M:%S")
        except:
            dt_expire = dt_now

        if dt_now >= dt_expire:
            log_attempt("FAILED: VIP Expired")
            return "VIP expirado!", 403

        stored_uid = user.get('UID')
        if stored_uid == "000000000000000":
            FirebaseDB.update_user(user['firebase_id'], {"UID": device_uid})
            stored_uid = device_uid
        
        if stored_uid != device_uid:
            log_attempt("FAILED: Device UID Mismatch")
            return "Dispositivo negado!", 403

        log_attempt("SUCCESS (GET)")
        return device_uid

    token_post = request.form.get('token')
    if not token_post:
        return token_response({"Status": "Failed", "MessageString": "Erro ao verificar seu login!"})

    try:
        token_bytes = base64.b64decode(token_post)
        tokarr = json.loads(token_bytes.decode('utf-8'))
        enc_data = tokarr.get('Data')
        dec_data_str = crypto.decrypt_by_private(enc_data)
        if not dec_data_str: raise ValueError("RSA Decryption failed")
        request_data = json.loads(dec_data_str)
    except Exception as e:
        return token_response({"Status": "Failed", "MessageString": f"Erro: {str(e)}"})

    username = request_data.get('app_Us')
    password = request_data.get('app_Pa')
    device_uid = request_data.get('app_ID')
    login_ref = request.args.get('gdfasdgertdfswsdf', '')

    def log_post_attempt(status):
        FirebaseDB.create_device_log({
            "username": username or "Unknown",
            "device_uid": device_uid or "Unknown",
            "ip": client_ip,
            "user_agent": user_agent,
            "phone_info": phone_info,
            "status": status,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

    user = FirebaseDB.get_user_by_username(username)
    if not user or user.get('senha') != password:
        log_post_attempt("FAILED: Invalid Credentials")
        return token_response({"Status": "Failed", "MessageString": "Login inválido!"})

    if user.get('status') == "0":
        log_post_attempt("FAILED: Banned User")
        return token_response({"Status": "Failed", "MessageString": "Banido!"})

    dt_now = datetime.now()
    try:
        dt_expire = datetime.strptime(user.get('expiracao'), "%Y-%m-%d %H:%M:%S")
    except:
        dt_expire = dt_now

    if dt_now >= dt_expire:
        log_post_attempt("FAILED: VIP Expired")
        return token_response({"Status": "Failed", "MessageString": "VIP expirado!"})

    stored_uid = user.get('UID')
    if stored_uid == "000000000000000":
        FirebaseDB.update_user(user['firebase_id'], {"UID": device_uid})
        stored_uid = device_uid
    
    if stored_uid != device_uid:
        log_post_attempt("FAILED: Device UID Mismatch")
        return token_response({"Status": "Failed", "MessageString": "Dispositivo negado!"})

    version_id = "V4" if login_ref == "x32v4" else "V3"
    loader_path = os.path.join(BASE_DIR, "loader", version_id, "PUBG.kmods")
    loader_b64 = ""
    if os.path.exists(loader_path):
        with open(loader_path, "rb") as f: loader_b64 = base64.b64encode(f.read()).decode()

    WebhookManager.discord_log(username, client_ip, login_ref)
    log_post_attempt("SUCCESS (POST)")

    return token_response({
        "Status": "Success",
        "Loader": loader_b64,
        "MessageString": f"{{'Cliente':{username},'Dias':{max(0, (dt_expire-dt_now).days)},'Game':{user.get('version', 'v1')}}}",
        "CurrUser": username, "CurrPass": password, "SubscriptionLeft": "1"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
