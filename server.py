import http.server
import socketserver
import urllib.parse
import urllib.request
import os
import json
import time
import secrets
import shutil

import qrcode
import io

PORT = 8080
SESSIONS = {} # {token: {"email": email, "expires": timestamp}}
QR_TOKENS = {} # {magic_token: {"email": email, "expires": timestamp}}
SESSION_DURATION = 300 # 5 minutes in seconds
QR_TOKEN_DURATION = 300 # 5 minutes
ADMIN_SESSION_DURATION = 3600 # 1 hour in seconds
ANALYTICS_FILE = 'analytics.json'
AUDIT_LOG_FILE = 'audit_logs.json'

def log_audit(user_email, action, details, os_type=None, env=None, version=None):
    """Log admin actions to audit_logs.json"""
    try:
        logs = []
        if os.path.exists(AUDIT_LOG_FILE):
            with open(AUDIT_LOG_FILE, 'r') as f:
                logs = json.load(f)
        
        entry = {
            'time': int(time.time()),
            'email': user_email,
            'action': action,
            'details': details,
            'os': os_type,
            'env': env,
            'version': version
        }
        
        logs.insert(0, entry) # Newest first
        logs = logs[:500] # Keep last 500 actions
        
        with open(AUDIT_LOG_FILE, 'w') as f:
            json.dump(logs, f, indent=4)
    except Exception as e:
        print(f"Error logging audit: {e}")

def load_env():
    env = {}
    try:
        if os.path.exists('.env'):
            with open('.env', 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '=' in line:
                        key, value = line.split('=', 1)
                        env[key.strip()] = value.strip()
    except Exception as e:
        print(f"Error loading .env: {e}")
    return env

def is_whitelisted(email):
    if not os.path.exists('whitelist.json'):
        return None
    try:
        with open('whitelist.json', 'r') as f:
            whitelist = json.load(f)
            for entry in whitelist:
                if entry.get('email', '').lower() == email.lower():
                    return entry
    except Exception as e:
        print(f"Error reading whitelist: {e}")
    return None

def get_admins():
    env = load_env()
    admin_str = env.get('ADMIN_EMAILS', '')
    return [e.strip().lower() for e in admin_str.split(',') if e.strip()]

def get_super_admins():
    env = load_env()
    super_admin_str = env.get('SUPER_ADMIN_EMAILS', '')
    return [e.strip().lower() for e in super_admin_str.split(',') if e.strip()]

def is_admin(email):
    return email.lower() in get_admins()

def is_super_admin(email):
    return email.lower() in get_super_admins()

def send_push_notification(app_data, os_type):
    """
    Send push notification when a new app version is added.
    app_data should contain: appName, version, environment, date
    os_type should be 'android' or 'ios'
    """
    env = load_env()
    push_url = env.get('PUSH_NOTIFICATION_URL', '')
    push_header = env.get('PUSH_NOTIFICATION_HEADER', '')
    
    # Skip if URL is empty or "-"
    if not push_url or push_url == '-':
        return
    
    # Skip if header is empty or "-"
    if not push_header or push_header == '-':
        return
    
    try:
        # Load whitelist data
        whitelist_data = []
        if os.path.exists('whitelist.json'):
            with open('whitelist.json', 'r') as f:
                whitelist_data = json.load(f)
        
        # Prepare notification payload
        payload = {
            'app_name': app_data.get('appName', ''),
            'version': app_data.get('version', ''),
            'environment': app_data.get('environment', 'prod'),
            'release_date': app_data.get('date', ''),
            'os_type': os_type,
            'app_installer_url': env.get('APP_INSTALLER_URL', ''),
            'whitelist': whitelist_data
        }
        
        # Prepare request
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            push_url,
            data=data,
            headers={
                'Content-Type': 'application/json',
                'X-Secret-Access': push_header
            },
            method='POST'
        )
        
        # Send request
        with urllib.request.urlopen(req, timeout=10) as response:
            print(f"Push notification sent successfully: {response.status}")
            
    except Exception as e:
        print(f"Failed to send push notification: {e}")

def log_download(filename, user_name="Guest", user_email="Guest"):
    """Log a download event to analytics.json using version|env as key"""
    print(f"DEBUG: Processing download log for {filename} by {user_email}")
    try:
        data = {}
        if os.path.exists(ANALYTICS_FILE):
            with open(ANALYTICS_FILE, 'r') as f:
                data = json.load(f)
        
        # Try to find version/env info for the filename
        version = "Unknown Version"
        env = "prod"
        
        found_os = "unknown"
        found = False
        for os_type in ['android', 'ios']:
            v_file = f'public/{os_type}_versions.json'
            if os.path.exists(v_file):
                with open(v_file, 'r') as f:
                    try:
                        v_list = json.load(f)
                        file_key = 'apkFile' if os_type == 'android' else 'ipaFile'
                        for v in v_list:
                            if v.get(file_key) == filename:
                                version = v.get('version', 'Unknown')
                                env = v.get('environment', 'prod')
                                found_os = os_type
                                found = True
                                break
                    except Exception as e:
                        print(f"DEBUG: Error reading {v_file}: {e}")
            if found: break

        key = f"{found_os}|{version}|{env}"
        print(f"DEBUG: Analytics key determined as: {key}")
        today = time.strftime('%Y-%m-%d')
        
        if key not in data:
            data[key] = {'total': 0, 'daily': {}, 'version': version, 'env': env, 'os': found_os}
            
        data[key]['total'] += 1
        data[key]['daily'][today] = data[key]['daily'].get(today, 0) + 1
        data[key]['last_download'] = int(time.time())
        
        # Track user who downloaded
        if 'downloads' not in data[key]:
            data[key]['downloads'] = []
            
        data[key]['downloads'].append({
            'name': user_name,
            'email': user_email,
            'time': int(time.time())
        })
        
        # Keep last 50 entries
        data[key]['downloads'] = data[key]['downloads'][-50:]
        
        with open(ANALYTICS_FILE, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"DEBUG: Successfully updated analytics for {key}")

    except Exception as e:
        print(f"ERROR in log_download: {e}")
        import traceback
        traceback.print_exc()

def cleanup_analytics():
    """Remove analytics entries for versions that no longer exist in both manifests"""
    if not os.path.exists(ANALYTICS_FILE):
        return
        
    try:
        active_keys = set()
        for os_type in ['android', 'ios']:
            v_file = f'public/{os_type}_versions.json'
            if os.path.exists(v_file):
                with open(v_file, 'r') as f:
                    try:
                        v_list = json.load(f)
                        for v in v_list:
                            ver = v.get('version', 'Unknown')
                            e = v.get('environment', 'prod')
                            active_keys.add(f"{os_type}|{ver}|{e}")
                    except: pass
        
        with open(ANALYTICS_FILE, 'r') as f:
            analytics = json.load(f)
            
        initial_count = len(analytics)
        # Keep only active keys
        cleaned_analytics = {k: v for k, v in analytics.items() if k in active_keys}
        
        if len(cleaned_analytics) != initial_count:
            with open(ANALYTICS_FILE, 'w') as f:
                json.dump(cleaned_analytics, f, indent=4)
            print(f"Cleaned up analytics: removed {initial_count - len(cleaned_analytics)} orphaned entries.")
            
    except Exception as e:
        print(f"Error cleaning analytics: {e}")

class Handler(http.server.SimpleHTTPRequestHandler):
    def get_session_token(self):
        cookies = self.headers.get('Cookie', '')
        for cookie in cookies.split(';'):
            if 'session_token=' in cookie:
                return cookie.split('session_token=')[1].strip()
        return None

    def is_authenticated(self):
        env = load_env()
        if env.get('SECURE_LOGIN', 'true').lower() == 'false':
            return True

        token = self.get_session_token()
        if not token or token not in SESSIONS:
            return False
        
        session = SESSIONS[token]
        if time.time() > session['expires']:
            del SESSIONS[token]
            return False
        
        return True

    def is_admin_authenticated(self):
        env = load_env()
        if env.get('SECURE_LOGIN_ADMIN', 'true').lower() == 'false':
            return True

        token = self.get_session_token()
        if not token or token not in SESSIONS:
            return False
        
        session = SESSIONS[token]
        if time.time() > session.get('expires', 0):
            return False
            
        return session.get('role') == 'admin' or session.get('is_super_admin', False)

    def is_super_admin_authenticated(self):
        token = self.get_session_token()
        if not token or token not in SESSIONS:
            return False
        
        session = SESSIONS[token]
        if time.time() > session.get('expires', 0):
            return False
            
        return session.get('is_super_admin', False)

    def do_POST(self):
        parsed_path = urllib.parse.urlparse(self.path)
        
        if parsed_path.path == '/login':
            env = load_env()
            if env.get('SECURE_LOGIN', 'true').lower() == 'false':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'success', 'message': 'Auth disabled'}).encode('utf-8'))
                return

            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            id_token = data.get('id_token')
            
            if not id_token:
                self.send_error(400, "Missing id_token")
                return

            try:
                verify_url = f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}"
                with urllib.request.urlopen(verify_url) as response:
                    token_info = json.loads(response.read().decode())
                    
                email = token_info.get('email')
                if not email: raise Exception("No email in token")
                
                super_admin_status = is_super_admin(email)
                admin_status = is_admin(email) or super_admin_status
                user_permissions = is_whitelisted(email)
                
                if not admin_status and not user_permissions:
                    self.send_response(403)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'error': 'Unauthorized', 'email': email}).encode('utf-8'))
                    return
                
                token = secrets.token_hex(32)
                duration = ADMIN_SESSION_DURATION if admin_status else SESSION_DURATION
                expires = time.time() + duration
                
                # Even for admins, we respect the whitelist for app permissions.
                # If they are NOT in the whitelist, they get NO app permissions by default.
                permissions = user_permissions or {
                    'availableOs': [],
                    'availableEnv': []
                }

                SESSIONS[token] = {
                    'email': email,
                    'name': token_info.get('name', email.split('@')[0]),
                    'expires': expires,
                    'role': 'admin' if admin_status else 'user',
                    'is_super_admin': super_admin_status,
                    'permissions': permissions
                }
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
                self.send_header('Set-Cookie', f'session_token={token}; Max-Age={duration}; Path=/; SameSite=Lax')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'success', 'expires': expires}).encode('utf-8'))
            except Exception as e:
                self.send_error(401, str(e))
            return

        if parsed_path.path == '/api/admin/whitelist':
            # Log whitelist update
            token = self.get_session_token()
            email = SESSIONS.get(token, {}).get('email', 'System')
            log_audit(email, 'Update Whitelist', 'Modified access permissions/user list')
            return self.api_update_whitelist()
            
        if parsed_path.path == '/api/admin/versions':
            # Note: Specific logging is handled inside api_update_versions for more detail
            return self.api_update_versions()

        if parsed_path.path == '/api/admin/upload':
            return self.api_upload_file()

        if parsed_path.path == '/api/admin/delete-file':
            return self.api_delete_file()

        self.send_response(404)
        self.end_headers()

    def api_get_whitelist(self):
        if not self.is_super_admin_authenticated():
            self.send_error(403)
            return
        data = []
        if os.path.exists('whitelist.json'):
            with open('whitelist.json', 'r') as f:
                data = json.load(f)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def api_update_whitelist(self):
        if not self.is_super_admin_authenticated():
            self.send_error(403)
            return
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            data = json.loads(self.rfile.read(content_length).decode())
            with open('whitelist.json', 'w') as f:
                json.dump(data, f, indent=4)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'success'}).encode())
        except Exception as e:
            self.send_error(500, str(e))

    def api_get_versions(self):
        if not self.is_admin_authenticated():
            self.send_error(403)
            return
        data = {'android': [], 'ios': []}
        try:
            if os.path.exists('public/android_versions.json'):
                with open('public/android_versions.json', 'r') as f:
                    data['android'] = json.load(f)
            if os.path.exists('public/ios_versions.json'):
                with open('public/ios_versions.json', 'r') as f:
                    data['ios'] = json.load(f)
        except: pass
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def api_get_analytics(self):
        if not self.is_admin_authenticated():
            self.send_error(403)
            return
        data = {}
        if os.path.exists(ANALYTICS_FILE):
            with open(ANALYTICS_FILE, 'r') as f:
                data = json.load(f)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def api_get_audit_logs(self):
        if not self.is_super_admin_authenticated():
            self.send_error(403)
            return
        logs = []
        if os.path.exists(AUDIT_LOG_FILE):
            with open(AUDIT_LOG_FILE, 'r') as f:
                logs = json.load(f)
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(logs).encode())

    def api_get_system_stats(self):
        if not self.is_admin_authenticated():
            self.send_error(403)
            return
        
        stats = {}
        try:
            total, used, free = shutil.disk_usage("/")
            stats = {
                'disk_total': total,
                'disk_used': used,
                'disk_free': free,
                'disk_percent': round((used / total) * 100, 1)
            }
        except Exception as e:
            print(f"Error getting system stats: {e}")
            
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(stats).encode())

    def api_get_qr_token(self):
        if not self.is_authenticated():
            self.send_error(401)
            return

        token = self.get_session_token()
        session = SESSIONS.get(token)
        if not session:
            self.send_error(401)
            return

        # Generate a short-lived magic token
        magic_token = secrets.token_urlsafe(16)
        QR_TOKENS[magic_token] = {
            'email': session.get('email', 'Guest'),
            'name': session.get('name', 'Guest'),
            'expires': time.time() + QR_TOKEN_DURATION
        }
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'token': magic_token}).encode())

    def api_get_qr_image(self, path):
        # Extract magic token and target URL from query
        query = urllib.parse.urlparse(path).query
        params = urllib.parse.parse_qs(query)
        token = params.get('token', [''])[0]
        url = params.get('url', [''])[0]
        
        if not token or not url:
            self.send_error(400)
            return

        # The URL might already have the magic_token embedded (for iOS itms-services URLs)
        # Only add it if not already present
        if 'magic_token=' not in url:
            # Check if URL already has query parameters
            separator = '&' if '?' in url else '?'
            magic_url = f"{url}{separator}magic_token={token}"
        else:
            # Token already in URL, use as-is
            magic_url = url
        
        # Generate QR
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(magic_url)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        
        # Write to buffer
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='PNG')
        img_byte_arr = img_byte_arr.getvalue()

        self.send_response(200)
        self.send_header('Content-Type', 'image/png')
        self.end_headers()
        self.wfile.write(img_byte_arr)

    def api_update_versions(self):
        if not self.is_admin_authenticated():
            self.send_error(403)
            return
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            data = json.loads(self.rfile.read(content_length).decode())
            os_type = data.get('os') # 'android' or 'ios'
            versions = data.get('versions', [])
            
            filename = 'public/android_versions.json' if os_type == 'android' else 'public/ios_versions.json'
            
            # Load existing versions to detect new additions
            existing_versions = []
            if os.path.exists(filename):
                try:
                    with open(filename, 'r') as f:
                        existing_versions = json.load(f)
                except:
                    pass
            
            # Save new versions
            with open(filename, 'w') as f:
                json.dump(versions, f, indent=4)
            
            # Detect newly added versions
            # Create a map of existing version identifiers to their data for comparison
            existing_map = {}
            for v in existing_versions:
                version_id = f"{v.get('appName', '')}|{v.get('version', '')}|{v.get('environment', 'prod')}"
                existing_map[version_id] = v
            
            # Check for new versions and send notifications
            token = self.get_session_token()
            email = SESSIONS.get(token, {}).get('email', 'System')
            
            for v in versions:
                version_id = f"{v.get('appName', '')}|{v.get('version', '')}|{v.get('environment', 'prod')}"
                v_num = v.get('version', 'Unknown')
                v_env = v.get('environment', 'prod')
                
                if version_id not in existing_map:
                    # This is a new version
                    print(f"New app version detected: {v.get('appName')} v{v_num} ({v_env})")
                    send_push_notification(v, os_type)
                    log_audit(email, 'Add Version', f"Added {v.get('appName')}", os_type, v_env, v_num)
                else:
                    # It exists, check if any details actually changed
                    old_v = existing_map[version_id]
                    # Compare key fields to see if "Update" is warranted
                    keys_to_compare = ['changelog', 'date', 'apkFile', 'ipaFile', 'bundleId']
                    changed = False
                    for k in keys_to_compare:
                        if v.get(k) != old_v.get(k):
                            changed = True
                            break
                    
                    if changed:
                        log_audit(email, 'Update Version', f"Modified {v.get('appName')}", os_type, v_env, v_num)
            
            # Detect deletions
            new_ids = {f"{v.get('appName', '')}|{v.get('version', '')}|{v.get('environment', 'prod')}" for v in versions}
            for v in existing_versions:
                old_id = f"{v.get('appName', '')}|{v.get('version', '')}|{v.get('environment', 'prod')}"
                if old_id not in new_ids:
                    log_audit(email, 'Delete Version', f"Removed {v.get('appName')}", os_type, v.get('environment', 'prod'), v.get('version', 'Unknown'))
                    
            # Cleanup analytics for deleted versions
            cleanup_analytics()
                
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'success'}).encode())
        except Exception as e:
            self.send_error(500, str(e))


    def api_upload_file(self):
        if not self.is_admin_authenticated():
            self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'error', 'error': 'Unauthorized'}).encode())
            return
        
        try:
            content_type = self.headers.get('Content-Type')
            content_length = int(self.headers.get('Content-Length', 0))
            if not content_type or 'multipart/form-data' not in content_type or content_length == 0:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'error', 'error': 'Invalid Request'}).encode())
                return
            
            # Read the entire body into memory for reliable parsing
            body = self.rfile.read(content_length)
            
            # Extract boundary
            parts = content_type.split("boundary=")
            boundary_str = parts[1].strip()
            if boundary_str.startswith('"') and boundary_str.endswith('"'):
                boundary_str = boundary_str[1:-1]
            boundary = b"--" + boundary_str.encode()
            
            # Split body by boundary
            sections = body.split(boundary)
            target_section = None
            filename = None
            
            for section in sections:
                if b'Content-Disposition' in section and b'filename=' in section:
                    target_section = section
                    import re
                    match = re.search(rb'filename="([^"]+)"', section)
                    if match:
                        filename = match.group(1).decode()
                    break
            
            if not target_section or not filename:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'error', 'error': 'No file found in upload'}).encode())
                return

            # Find the start of the file data (after the headers \r\n\r\n)
            header_end = target_section.find(b'\r\n\r\n')
            if header_end == -1:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'status': 'error', 'error': 'Invalid multi-part format'}).encode())
                return
            
            # The data starts after \r\n\r\n and ends before the trailing \r\n
            file_data = target_section[header_end + 4:]
            if file_data.endswith(b'\r\n'):
                file_data = file_data[:-2]
            
            # Determine destination
            ext = filename.split('.')[-1].lower()
            subdir = 'apk' if ext == 'apk' else 'ipa'
            save_path = f"public/downloads/{subdir}/{filename}"
            
            # Ensure directory exists
            import os
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            
            with open(save_path, 'wb') as f:
                f.write(file_data)

            response = json.dumps({'status': 'success', 'filename': filename}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)

            # Log upload
            try:
                token = self.get_session_token()
                email = SESSIONS.get(token, {}).get('email', 'System')
                os_type = 'android' if ext == 'apk' else 'ios'
                log_audit(email, 'Upload File', f"Uploaded {filename}", os_type=os_type)
            except: pass
            
            return
            
        except Exception as e:
            print(f"Upload error: {e}")
            import traceback
            traceback.print_exc()
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'error', 'error': str(e)}).encode())
            return

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        
        # Handle favicon.ico specially - redirect to /public/favicon.ico
        if parsed_path.path == '/favicon.ico':
            self.path = '/public/favicon.ico'
            return http.server.SimpleHTTPRequestHandler.do_GET(self)
        
        # Public assets that don't need auth
        public_paths = ['/style.css', '/main.js']
        # If the path is a public asset, serve it
        if any(parsed_path.path.startswith(p) for p in public_paths) or parsed_path.path.startswith('/public/'):
            # Log downloads for analytics and serve with proper headers for files in downloads
            if parsed_path.path.startswith('/public/downloads/'):
                filename = os.path.basename(parsed_path.path)
                if filename:
                    # Capture user info from session OR magic token
                    token = self.get_session_token()
                    
                    # Check for Magic Token in URL query
                    query = urllib.parse.urlparse(self.path).query
                    params = urllib.parse.parse_qs(query)
                    magic_token = params.get('magic_token', [''])[0]

                    user_name = "Guest"
                    user_email = "Guest"
                    
                    if magic_token and magic_token in QR_TOKENS:
                        qt = QR_TOKENS[magic_token]
                        if time.time() < qt['expires']:
                            user_name = qt.get('name', 'Guest')
                            user_email = qt.get('email', 'Guest')
                            # We don't delete immediately to allow retries if download fails?
                            # Or delete to make it one-time use? Let's keep it for the duration.
                    elif token and token in SESSIONS:
                        user_name = SESSIONS[token].get('name', 'Guest')
                        user_email = SESSIONS[token].get('email', 'Guest')
                        
                    log_download(filename, user_name, user_email)
                    
                    # Manually serve build files to include Content-Disposition header
                    file_path = parsed_path.path.lstrip('/')
                    if os.path.exists(file_path) and os.path.isfile(file_path):
                        self.send_response(200)
                        
                        # ANTI-CACHE HEADERS to ensure every download is logged in production
                        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0')
                        self.send_header('Pragma', 'no-cache')
                        self.send_header('Expires', '0')
                        
                        if file_path.endswith('.apk'):
                            self.send_header('Content-Type', 'application/vnd.android.package-archive')
                        elif file_path.endswith('.ipa'):
                            self.send_header('Content-Type', 'application/octet-stream')
                        else:
                            self.send_header('Content-Type', 'application/octet-stream')
                            
                        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                        self.send_header('Content-Length', str(os.path.getsize(file_path)))
                        self.end_headers()
                        
                        print(f"Serving download: {file_path} for {user_email}")
                        
                        with open(file_path, 'rb') as f:
                            import shutil
                            shutil.copyfileobj(f, self.wfile)
                        return
                    else:
                        print(f"Download file not found: {file_path}")

            return http.server.SimpleHTTPRequestHandler.do_GET(self)

        # Index page is technically public so it can show the login UI if not auth
        if parsed_path.path == '/' or parsed_path.path == '/index.html':
            return self.serve_index()

        if parsed_path.path == '/config':
            return self.serve_config()

        if parsed_path.path == '/admin' or parsed_path.path == '/admin/':
            return self.serve_admin()

        if parsed_path.path == '/api/admin/whitelist':
            return self.api_get_whitelist()
        
        if parsed_path.path == '/api/admin/versions':
            return self.api_get_versions()

        if parsed_path.path == '/api/admin/analytics':
            return self.api_get_analytics()

        if parsed_path.path == '/api/admin/audit-logs':
            return self.api_get_audit_logs()

        if parsed_path.path == '/api/admin/system-stats':
            return self.api_get_system_stats()

        if parsed_path.path == '/logout':
            token = self.get_session_token()
            if token in SESSIONS:
                del SESSIONS[token]
            self.send_response(200)
            self.send_header('Set-Cookie', 'session_token=; Max-Age=0; Path=/')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'success'}).encode('utf-8'))
            return
        if parsed_path.path in ['/manifest.plist', '/install-ios.html']:
            if parsed_path.path == '/manifest.plist':
                return self.serve_manifest(parsed_path)
            return http.server.SimpleHTTPRequestHandler.do_GET(self)

        # Check authentication for protected routes
        if not self.is_authenticated():
            self.send_response(401)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Unauthorized'}).encode('utf-8'))
            return

        if parsed_path.path == '/api/user/versions':
            return self.api_serve_user_versions(parsed_path)
            
        if parsed_path.path == '/api/qr/token':
            return self.api_get_qr_token()

        if parsed_path.path == '/api/qr/image':
            return self.api_get_qr_image(self.path)

        return http.server.SimpleHTTPRequestHandler.do_GET(self)

    def api_delete_file(self):
        if not self.is_admin_authenticated():
            self.send_error(403)
            return
        
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            data = json.loads(self.rfile.read(content_length).decode())
            filename = data.get('filename')
            os_type = data.get('os') # 'android' or 'ios'
            
            if not filename or not os_type:
                self.send_error(400, "Missing filename or os")
                return
                
            subdir = 'apk' if os_type == 'android' else 'ipa'
            # Security: Ensure filename doesn't contain path traversal
            safe_filename = os.path.basename(filename)
            file_path = f"public/downloads/{subdir}/{safe_filename}"
            
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"Deleted file: {file_path}")
            
            response = json.dumps({'status': 'success'}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)

            # Log deletion
            try:
                token = self.get_session_token()
                email = SESSIONS.get(token, {}).get('email', 'System')
                log_audit(email, 'Delete File', f"Deleted {filename} asset", os_type=os_type)
            except: pass
        except Exception as e:
            print(f"Delete error: {e}")
            self.send_error(500, str(e))
        return

    def serve_admin(self):
        # Admin ALWAYS needs authentication via Google, regardless of SECURE_LOGIN setting
        if not self.is_admin_authenticated():
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()
            return
            
        try:
            with open('admin.html', 'r', encoding='utf-8') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            self.end_headers()
            self.wfile.write(content.encode('utf-8'))
        except Exception as e:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Admin portal not found.")

    def serve_index(self):
        env = load_env()
        app_name = env.get('APP_NAME', 'App Installer')
        google_client_id = env.get('GOOGLE_CLIENT_ID', '')
        
        try:
            with open('index.html', 'r', encoding='utf-8') as f:
                content = f.read()
            
            content = content.replace("<title>App Installer</title>", f"<title>{app_name}</title>")
            content = content.replace('<h1 id="app-title">...</h1>', f'<h1 id="app-title">{app_name}</h1>')
            content = content.replace("© ... All rights reserved.", f"© 2025 {app_name}. All rights reserved.")
            
            # Inject Google Client ID if available
            if google_client_id:
                content = content.replace('<!-- GOOGLE_CLIENT_ID_PLACEHOLDER -->', google_client_id)
            
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(content.encode('utf-8'))
        except Exception as e:
            print(f"Error serving index: {e}")
            self.send_response(500)
            self.end_headers()

    def serve_config(self):
        env = load_env()
        token = self.get_session_token()
        session = SESSIONS.get(token, {}) if token else {}
        expires = session.get('expires', 0)
        is_user_admin = session.get('role') == 'admin'
        
        app_templates = {}
        if os.path.exists('app_config.json'):
            try:
                with open('app_config.json', 'r') as f:
                    app_templates = json.load(f)
            except: pass

        config = {
            'appName': env.get('APP_NAME', 'App Installer'),
            'googleClientId': env.get('GOOGLE_CLIENT_ID', ''),
            'expires': expires,
            'secureLogin': env.get('SECURE_LOGIN', 'true').lower() != 'false',
            'isAdmin': is_user_admin if env.get('SECURE_LOGIN_ADMIN', 'true').lower() == 'true' else True,
            'isSuperAdmin': session.get('is_super_admin', False),
            'timezone': env.get('TIMEZONE', 'UTC'),
            'permissions': session.get('permissions', {}),
            'appTemplates': app_templates
        }
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.end_headers()
        self.wfile.write(json.dumps(config).encode('utf-8'))

    def api_serve_user_versions(self, parsed_path):
        if not self.is_authenticated():
            self.send_error(401)
            return

        query = urllib.parse.parse_qs(parsed_path.query)
        os_type = query.get('os', ['android'])[0].lower()
        
        token = self.get_session_token()
        session = SESSIONS.get(token, {})
        permissions = session.get('permissions', {})
        
        # Determine defaults based on global security settings
        env = load_env()
        login_disabled = env.get('SECURE_LOGIN', 'true').lower() == 'false'
        
        # Check OS Permission
        # If login is disabled, we allow everything. If enabled, we MUST have a permission entry.
        if login_disabled:
            allowed_os = ['android', 'ios']
        else:
            allowed_os = permissions.get('availableOs', [])
            
        if os_type not in allowed_os:
            response = json.dumps([]).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)
            return

        # Load data
        filename = f'public/{os_type}_versions.json'
        data = []
        if os.path.exists(filename):
            try:
                with open(filename, 'r') as f:
                    data = json.load(f)
            except: pass

        # Filter by Environment Permission
        if login_disabled:
            allowed_envs = ['stg', 'rc', 'prod']
        else:
            allowed_envs = permissions.get('availableEnv', [])
            
        filtered_data = [v for v in data if (v.get('environment') or 'prod') in allowed_envs]

        response = json.dumps(filtered_data).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def serve_manifest(self, parsed_path):
        query = urllib.parse.parse_qs(parsed_path.query)
        app_name = query.get('appName', ['App Installer'])[0]
        bundle_id = query.get('bundleId', ['com.example.app'])[0]
        version = query.get('version', ['1.0.0'])[0]
        ipa_filename = query.get('ipa', ['app.ipa'])[0]
        
        host = self.headers.get('Host')
        scheme = "https"
        if "localhost" in host:
             scheme = "http"
             
        # Build IPA URL with magic_token if present
        ipa_url = f"{scheme}://{host}/public/downloads/ipa/{ipa_filename}"
        
        # Preserve magic_token from the manifest URL to the IPA URL
        magic_token = query.get('magic_token', [None])[0]
        if magic_token:
            ipa_url += f"?magic_token={magic_token}"

        manifest_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>items</key>
    <array>
        <dict>
            <key>assets</key>
            <array>
                <dict>
                    <key>kind</key>
                    <string>software-package</string>
                    <key>url</key>
                    <string>{ipa_url}</string>
                </dict>
            </array>
            <key>metadata</key>
            <dict>
                <key>bundle-identifier</key>
                <string>{bundle_id}</string>
                <key>bundle-version</key>
                <string>{version}</string>
                <key>kind</key>
                <string>software</string>
                <key>title</key>
                <string>{app_name}</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>"""
        
        self.send_response(200)
        # Use application/xml for proper iOS handling
        self.send_header("Content-Type", "application/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(manifest_xml.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(manifest_xml.encode('utf-8'))

print(f"Serving at port {PORT}")
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    httpd.serve_forever()
