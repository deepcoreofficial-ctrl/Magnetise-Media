from flask import Flask, request, jsonify, session, redirect, render_template, url_for
from flask_mysqldb import MySQL
from passlib.hash import pbkdf2_sha256
import uuid
import os
import random
import time
from dotenv import load_dotenv
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta
import re
from flask_cors import CORS

load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.permanent_session_lifetime = timedelta(days=7)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.getenv("FLASK_ENV") == "production"
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.secret_key = os.getenv("SECRET_KEY")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)


# MySQL config
from urllib.parse import urlparse

db_url = urlparse(os.getenv("MYSQL_URL"))

app.config['MYSQL_HOST'] = db_url.hostname
app.config['MYSQL_USER'] = db_url.username
app.config['MYSQL_PASSWORD'] = db_url.password
app.config['MYSQL_DB'] = db_url.path[1:]
app.config['MYSQL_PORT'] = db_url.port
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)

# In-memory OTP store: { email: { 'otp': '123456', 'name': '...', 'expires': timestamp } }
otp_store = {}
reset_otp_store = {}

def create_tables():
    with app.app_context():
        try:
            cur = mysql.connection.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS password_reset_requests (
                    email VARCHAR(255) PRIMARY KEY,
                    full_name VARCHAR(255),
                    status ENUM('PENDING','DONE') DEFAULT 'PENDING',
                    requested_at DATETIME
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS views_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    campaign_id VARCHAR(20),
                    views INT NOT NULL,
                    recorded_at DATETIME DEFAULT NOW(),
                    INDEX idx_campaign (campaign_id)
                )
            """)
            mysql.connection.commit()
            cur.close()
        except Exception as e:
            print(f"Table init error: {e}")

# ==========================================
# BREVO HELPER
# ==========================================

def send_brevo_email(to_email, to_name, subject, html_content):
    configuration = sib_api_v3_sdk.Configuration()
    configuration.host = "https://api.brevo.com/v3"
    configuration.api_key['api-key'] = os.getenv('BREVO_API_KEY')
    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
        sib_api_v3_sdk.ApiClient(configuration)
    )
    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": to_email, "name": to_name}],
        sender={"email": os.getenv('MAIL_FROM'), "name": "Magnetise Media"},
        subject=subject,
        html_content=html_content
    )
    api_instance.send_transac_email(send_smtp_email)

# ==========================================
# WEBSITE PAGES
# ==========================================

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

# ==========================================
# CLIENT AUTH ROUTES
# ==========================================

@app.route('/client-login')
def client_login():
    if 'user_email' in session:
        return redirect(url_for('client_dashboard'))
    return render_template('dashboard_login.html')

@app.route('/signup')
def signup():
    return render_template('dashboard_signup.html')

@app.route('/dashboard')
def client_dashboard():
    if 'user_email' not in session:
        return redirect(url_for('client_login'))
    return render_template('dashboard_main.html', email=session['user_email'])

@app.route('/dashboard/logout')
def logout():
    session.clear()
    return redirect(url_for('client_login'))

# ==========================================
# CLIENT API
# ==========================================

@app.route('/api/auth/check-email', methods=['POST'])
def check_email():
    data = request.get_json()
    email = data.get('email', '').strip().lower()

    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, account_status FROM users WHERE email=%s", (email,))
    user = cur.fetchone()
    cur.close()

    return jsonify({
        'success': True,
        'exists': bool(user),
        'status': user['account_status'] if user else None
    })


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def api_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({'success': False, 'message': 'No account found'})

    if user['account_status'] != 'ACTIVE':
        return jsonify({'success': False, 'message': 'Account not active'})

    if not pbkdf2_sha256.verify(password, user['password_hash']):
        return jsonify({'success': False, 'message': 'Incorrect password'})

    session.permanent = True
    session['user_email'] = email
    return jsonify({'success': True})


# ==========================================
# OTP SIGNUP FLOW
# ==========================================

@app.route('/api/auth/send-otp', methods=['POST'])
@limiter.limit("3 per minute")
def send_otp():
    data = request.get_json()
    name = data.get('full_name', '').strip()
    email = data.get('email', '').strip().lower()

    if not name or not email:
        return jsonify({'success': False, 'message': 'Name and email are required.'})

    email_regex = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'

    if not re.match(email_regex, email):
        return jsonify({'success': False, 'message': 'Invalid email format.'})

    # Check if email already registered
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id FROM users WHERE email=%s", (email,))
    existing = cur.fetchone()
    cur.close()

    if existing:
        return jsonify({'success': False, 'message': 'An account with this email already exists.'})

    # Generate 6-digit OTP
    otp = str(random.randint(100000, 999999))
    otp_store[email] = {
        'otp': otp,
        'name': name,
        'expires': time.time() + 600  # 10 minutes
    }

    # Email template — black & white, Magnetise Media branding
    html_content = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:'Helvetica Neue',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:40px 16px;">
  <tr><td align="center">
    <table width="520" cellpadding="0" cellspacing="0" style="max-width:520px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;border:1px solid #e8e8e8;">

      <!-- HEADER -->
      <tr><td style="background:#0a0a0a;padding:32px 40px;text-align:center;">
        <div style="font-size:26px;font-weight:900;color:#ffffff;letter-spacing:-1px;">Magnetise Media</div>
        <div style="font-size:13px;color:#888888;margin-top:4px;">Email Verification</div>
      </td></tr>

      <!-- BODY -->
      <tr><td style="padding:36px 40px;">
        <p style="font-size:16px;color:#1a1a1a;margin:0 0 12px;">Hey <strong>{name}</strong>,</p>
        <p style="font-size:14px;color:#555555;line-height:1.7;margin:0 0 28px;">
          Use the verification code below to complete your Magnetise Media account signup.
          This code expires in <strong>10 minutes</strong>.
        </p>

        <!-- OTP BOX -->
        <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
          <tr><td align="center">
            <div style="display:inline-block;background:#0a0a0a;color:#ffffff;font-size:36px;font-weight:900;letter-spacing:14px;padding:20px 36px;border-radius:8px;font-family:'Courier New',monospace;">{otp}</div>
          </td></tr>
        </table>

        <p style="font-size:13px;color:#999999;line-height:1.7;margin:0 0 8px;text-align:center;">
          If you didn't request this, you can safely ignore this email.
        </p>
      </td></tr>

      <!-- FOOTER -->
      <tr><td style="border-top:1px solid #eeeeee;padding:20px 40px;text-align:center;background:#fafafa;">
        <p style="font-size:12px;color:#aaaaaa;margin:0;">
          Magnetise Media &nbsp;·&nbsp;
          <a href="mailto:magnetisemedia.co@gmail.com" style="color:#555555;text-decoration:none;">magnetisemedia.co@gmail.com</a>
        </p>
      </td></tr>

    </table>
  </td></tr>
</table>
</body>
</html>"""

    try:
        send_brevo_email(email, name, "Your Magnetise Media Verification Code", html_content)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Could not send email: {str(e)}'})


@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    otp = data.get('otp', '').strip()

    record = otp_store.get(email)

    if not record:
        return jsonify({'success': False, 'message': 'No verification code found. Please request a new one.'})

    if time.time() > record['expires']:
        otp_store.pop(email, None)
        return jsonify({'success': False, 'message': 'Code has expired. Please request a new one.'})

    if record['otp'] != otp:
        return jsonify({'success': False, 'message': 'Incorrect code. Please try again.'})

    # OTP valid — create user in DB
    name = record['name']
    otp_store.pop(email, None)

    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO users (user_id, full_name, email, account_status) VALUES (%s,%s,%s,'PENDING')",
            (str(uuid.uuid4()), name, email)
        )
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        return jsonify({'success': False, 'message': 'Account creation failed. Email may already exist.'})

    return jsonify({'success': True})


@app.route('/api/auth/signup', methods=['POST'])
def api_signup():
    # Legacy fallback (not used with OTP flow)
    data = request.get_json()
    name = data.get('full_name')
    email = data.get('email')

    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO users (user_id, full_name, email, account_status) VALUES (%s,%s,%s,'PENDING')",
                (str(uuid.uuid4()), name, email))
    mysql.connection.commit()
    cur.close()

    return jsonify({'success': True})


# ==========================================
# ADMIN ROUTES
# ==========================================

@app.route('/admin')
def admin():
    if not session.get('admin_logged_in'):
        return render_template('admin_login.html')
    return redirect('/admin/dashboard')

@app.route('/admin-login')
def admin_login_page():
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect('/admin')
    return render_template('admin_dashboard.html')

# ==========================================
# ADMIN API
# ==========================================

@app.route('/api/admin/login', methods=['POST'])
@limiter.limit("5 per minute")
def admin_login():
    data = request.get_json()
    email = data.get('email', '').strip()
    password = data.get('password', '').strip()

    if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
        session.permanent = True
        session['admin_logged_in'] = True
        session['admin_email'] = email
        return jsonify({'success': True})

    return jsonify({'success': False, 'message': 'Invalid credentials'})

@app.route('/api/admin/check')
def admin_check():
    if session.get('admin_logged_in'):
        return jsonify({'authenticated': True, 'email': session.get('admin_email', '')})
    return jsonify({'authenticated': False}), 401

@app.route('/api/admin/logout', methods=['POST'])
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_email', None)
    return jsonify({'success': True})

@app.route('/api/admin/pending')
def pending():
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, full_name, email, created_at FROM users WHERE account_status='PENDING' ORDER BY created_at DESC")
    users = cur.fetchall()
    cur.close()
    for u in users:
        u['created_at'] = str(u['created_at'])
    return jsonify({'success': True, 'users': users})

@app.route('/api/admin/stats')
def admin_stats():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    cur = mysql.connection.cursor()
    cur.execute("SELECT account_status, COUNT(*) as cnt FROM users GROUP BY account_status")
    rows = cur.fetchall()
    cur.execute("SELECT COUNT(*) as cnt FROM campaigns WHERE status='ACTIVE'")
    active = cur.fetchone()
    cur.execute("SELECT COUNT(*) as cnt FROM campaigns WHERE status='COMPLETED'")
    completed = cur.fetchone()
    cur.close()
    stats = {r['account_status']: r['cnt'] for r in rows}
    return jsonify({
        'success': True,
        'pending': stats.get('PENDING', 0),
        'active': active['cnt'],
        'total': sum(stats.values()),
        'completed': completed['cnt']
    })

@app.route('/api/admin/clients')
def admin_clients():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT u.user_id, u.full_name, u.email, u.account_status,
               c.campaign_id, c.campaign_name, c.current_views, c.login_email_sent_at
        FROM users u
        LEFT JOIN campaigns c ON u.campaign_id = c.campaign_id
        ORDER BY u.created_at DESC
    """)
    clients = cur.fetchall()
    cur.close()
    for c in clients:
        c['email_sent'] = bool(c.get('login_email_sent_at'))
        c['login_email_sent_at'] = str(c['login_email_sent_at']) if c['login_email_sent_at'] else None
    return jsonify({'success': True, 'clients': clients})

@app.route('/api/admin/reject', methods=['POST'])
def reject():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    data = request.get_json()
    email = data.get('email')
    reason = data.get('reason', '')
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET account_status='REJECTED', rejection_reason=%s WHERE email=%s", (reason, email))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

@app.route('/api/admin/create-campaign', methods=['POST'])
def admin_create_campaign():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    data = request.get_json()
    client_email = data.get('client_email')
    campaign_name = data.get('campaign_name')
    budget = data.get('budget_total')
    views = data.get('target_views')
    start = data.get('start_date')
    end = data.get('expected_end_date')
    password = data.get('password')
    if not all([client_email, campaign_name, budget, views, start, end, password]):
        return jsonify({'success': False, 'message': 'All fields required'}), 400
    password_hash = pbkdf2_sha256.hash(password)
    from datetime import datetime
    campaign_id = 'CX-' + datetime.now().strftime('%Y%m%d%H%M%S')
    cur = mysql.connection.cursor()
    cur.execute("""INSERT INTO campaigns (campaign_id, client_email, campaign_name, budget_total, target_views, start_date, expected_end_date, status, created_by)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,'ACTIVE',%s)""",
                (campaign_id, client_email, campaign_name, budget, views, start, end, session['admin_email']))
    cur.execute("UPDATE users SET account_status='ACTIVE', password_hash=%s, campaign_id=%s WHERE email=%s",
                (password_hash, campaign_id, client_email))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True, 'campaign_id': campaign_id, 'campaign_name': campaign_name})

@app.route('/api/admin/send-email', methods=['POST'])
def admin_send_email():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401

    data = request.get_json()
    client_email = data.get('client_email')
    client_password = data.get('password', '')

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT u.full_name, u.email, c.campaign_name, c.campaign_id,
               c.budget_total, c.target_views, c.start_date, c.expected_end_date
        FROM users u
        JOIN campaigns c ON u.campaign_id = c.campaign_id
        WHERE u.email = %s
    """, (client_email,))
    info = cur.fetchone()
    cur.close()

    if not info:
        return jsonify({'success': False, 'message': 'Client or campaign not found'}), 404

    subject = "Your Campaign is Ready — Login Details"
    html_content = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:'Helvetica Neue',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:40px 16px;">
  <tr><td align="center">
    <table width="520" cellpadding="0" cellspacing="0" style="max-width:520px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;border:1px solid #e8e8e8;">

      <!-- HEADER -->
      <tr><td style="background:#0a0a0a;padding:32px 40px;text-align:center;">
        <div style="font-size:26px;font-weight:900;color:#ffffff;letter-spacing:-1px;">Magnetise Media</div>
        <div style="font-size:13px;color:#888888;margin-top:4px;">Campaign Dashboard Access</div>
      </td></tr>

      <!-- BODY -->
      <tr><td style="padding:36px 40px;">
        <p style="font-size:16px;color:#1a1a1a;margin:0 0 12px;">Hey <strong>{info['full_name']}</strong>,</p>
        <p style="font-size:14px;color:#555555;line-height:1.7;margin:0 0 28px;">
          Your campaign is live and ready. Below are your campaign details and login credentials for the Magnetise Media dashboard.
        </p>

        <!-- CAMPAIGN DETAILS -->
        <div style="font-size:11px;font-weight:700;color:#999999;letter-spacing:0.08em;text-transform:uppercase;margin-bottom:8px;">Campaign Details</div>
        <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:20px;border:1px solid #e8e8e8;border-radius:6px;overflow:hidden;">
          <tr style="background:#f9f9f9;"><td style="padding:10px 16px;font-size:13px;color:#888888;">Campaign</td><td style="padding:10px 16px;font-size:13px;color:#1a1a1a;font-weight:600;text-align:right;">{info['campaign_name']}</td></tr>
          <tr><td style="padding:10px 16px;font-size:13px;color:#888888;border-top:1px solid #f0f0f0;">Campaign ID</td><td style="padding:10px 16px;font-size:13px;color:#1a1a1a;font-weight:700;text-align:right;border-top:1px solid #f0f0f0;font-family:'Courier New',monospace;">{info['campaign_id']}</td></tr>
          <tr style="background:#f9f9f9;"><td style="padding:10px 16px;font-size:13px;color:#888888;border-top:1px solid #f0f0f0;">Budget</td><td style="padding:10px 16px;font-size:13px;color:#1a1a1a;font-weight:600;text-align:right;border-top:1px solid #f0f0f0;">${info['budget_total']:,.0f}</td></tr>
          <tr><td style="padding:10px 16px;font-size:13px;color:#888888;border-top:1px solid #f0f0f0;">Target Views</td><td style="padding:10px 16px;font-size:13px;color:#1a1a1a;font-weight:600;text-align:right;border-top:1px solid #f0f0f0;">{info['target_views']:,}</td></tr>
          <tr style="background:#f9f9f9;"><td style="padding:10px 16px;font-size:13px;color:#888888;border-top:1px solid #f0f0f0;">Duration</td><td style="padding:10px 16px;font-size:13px;color:#1a1a1a;font-weight:600;text-align:right;border-top:1px solid #f0f0f0;">{str(info['start_date'])} → {str(info['expected_end_date'])}</td></tr>
        </table>

        <!-- LOGIN CREDENTIALS -->
        <div style="font-size:11px;font-weight:700;color:#999999;letter-spacing:0.08em;text-transform:uppercase;margin-bottom:8px;">Login Credentials</div>
        <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:32px;border:1px solid #e8e8e8;border-radius:6px;overflow:hidden;">
          <tr style="background:#f9f9f9;"><td style="padding:10px 16px;font-size:13px;color:#888888;">Email</td><td style="padding:10px 16px;font-size:13px;color:#1a1a1a;font-weight:600;text-align:right;">{info['email']}</td></tr>
          <tr><td style="padding:10px 16px;font-size:13px;color:#888888;border-top:1px solid #f0f0f0;">Password</td><td style="padding:10px 16px;text-align:right;border-top:1px solid #f0f0f0;"><span style="background:#f0f0f0;color:#1a1a1a;font-family:'Courier New',monospace;font-size:15px;font-weight:700;padding:4px 12px;border-radius:4px;">{client_password}</span></td></tr>
        </table>

        <!-- CTA -->
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr><td align="center">
            <a href="https://magnetise.media/client-login" style="display:inline-block;background:#0a0a0a;color:#ffffff;font-weight:700;font-size:15px;padding:14px 44px;border-radius:6px;text-decoration:none;letter-spacing:0.02em;">Login to Dashboard →</a>
          </td></tr>
        </table>
      </td></tr>

      <!-- FOOTER -->
      <tr><td style="border-top:1px solid #eeeeee;padding:20px 40px;text-align:center;background:#fafafa;">
        <p style="font-size:12px;color:#aaaaaa;margin:0;">
          Magnetise Media &nbsp;·&nbsp;
          <a href="mailto:magnetisemedia.co@gmail.com" style="color:#555555;text-decoration:none;">magnetisemedia.co@gmail.com</a>
        </p>
      </td></tr>

    </table>
  </td></tr>
</table>
</body>
</html>"""

    try:
        send_brevo_email(client_email, info['full_name'], subject, html_content)

        cur = mysql.connection.cursor()
        cur.execute("UPDATE campaigns SET login_email_sent_at=NOW() WHERE client_email=%s", (client_email,))
        mysql.connection.commit()
        cur.close()

        return jsonify({'success': True, 'message': f'Email sent to {client_email}'})

    except ApiException as e:
        return jsonify({'success': False, 'message': f'Email error: {str(e)}'}), 500

@app.route('/api/admin/complete-campaign', methods=['POST'])
def admin_complete_campaign():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    data = request.get_json()
    campaign_id = data.get('campaign_id')
    cur = mysql.connection.cursor()
    cur.execute("UPDATE campaigns SET status='COMPLETED' WHERE campaign_id=%s", (campaign_id,))
    cur.execute("UPDATE users SET account_status='ACTIVE' WHERE campaign_id=%s", (campaign_id,))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

@app.route('/api/admin/update-views', methods=['POST'])
def update_views():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    data = request.get_json()
    campaign_id = data.get('campaign_id')
    current_views = data.get('current_views')
    cur = mysql.connection.cursor()
    cur.execute("UPDATE campaigns SET current_views=%s WHERE campaign_id=%s", (current_views, campaign_id))
    cur.execute("INSERT INTO views_history (campaign_id, views) VALUES (%s, %s)", (campaign_id, current_views))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

@app.route('/api/admin/reactivate-client', methods=['POST'])
def reactivate_client():

    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401

    data = request.get_json()
    user_id = data.get('user_id')

    try:
        cur = mysql.connection.cursor()

        cur.execute("""
            UPDATE users
            SET account_status='PENDING',
                rejection_reason=NULL
            WHERE user_id=%s
        """, (user_id,))

        mysql.connection.commit()
        cur.close()

        return jsonify({'success': True})

    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        })


@app.route('/api/admin/delete-client', methods=['POST'])
def delete_client():

    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401

    data = request.get_json()
    user_id = data.get('user_id')

    try:

        cur = mysql.connection.cursor()

        # find campaign first
        cur.execute(
            "SELECT campaign_id FROM users WHERE user_id=%s",
            (user_id,)
        )

        user = cur.fetchone()

        if user and user.get('campaign_id'):

            campaign_id = user['campaign_id']

            # delete related campaign data
            cur.execute(
                "DELETE FROM views_history WHERE campaign_id=%s",
                (campaign_id,)
            )

            cur.execute(
                "DELETE FROM campaigns WHERE campaign_id=%s",
                (campaign_id,)
            )

        # delete user
        cur.execute(
            "DELETE FROM users WHERE user_id=%s",
            (user_id,)
        )

        mysql.connection.commit()
        cur.close()

        return jsonify({'success': True})

    except Exception as e:

        return jsonify({
            'success': False,
            'message': str(e)
        })
    
# ==========================================
# CLIENT DASHBOARD DATA
# ==========================================

@app.route('/api/dashboard/data')
def dashboard_data():
    if 'user_email' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    email = session['user_email']
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT u.full_name, u.email, u.account_status,
            c.campaign_id, c.campaign_name, c.budget_total,
            c.target_views, c.current_views, c.status,
            c.start_date, c.expected_end_date, c.cpm_rate
        FROM users u
        LEFT JOIN campaigns c ON u.campaign_id = c.campaign_id
        WHERE u.email = %s
    """, (email,))
    row = cur.fetchone()
    cur.close()

    if not row:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    if row.get('start_date'):
        row['start_date'] = str(row['start_date'])
    if row.get('expected_end_date'):
        row['expected_end_date'] = str(row['expected_end_date'])

    return jsonify({'success': True, 'data': row})

@app.route('/api/dashboard/top-clips')
def dashboard_top_clips():
    if 'user_email' not in session:
        return jsonify({'success': False}), 401
    cur = mysql.connection.cursor()
    cur.execute("SELECT campaign_id FROM users WHERE email=%s", (session['user_email'],))
    user = cur.fetchone()
    if not user or not user['campaign_id']:
        return jsonify({'success': True, 'clips': []})
    cur.execute("SELECT clipper_name, platform, views, url FROM top_clips WHERE campaign_id=%s AND views>=10000 ORDER BY views DESC", (user['campaign_id'],))
    clips = cur.fetchall()
    cur.close()
    return jsonify({'success': True, 'clips': clips})

@app.route('/api/dashboard/leaderboard')
def dashboard_leaderboard():
    if 'user_email' not in session:
        return jsonify({'success': False}), 401
    cur = mysql.connection.cursor()
    cur.execute("SELECT campaign_id FROM users WHERE email=%s", (session['user_email'],))
    user = cur.fetchone()
    if not user or not user['campaign_id']:
        return jsonify({'success': True, 'leaderboard': []})
    cur.execute("SELECT clipper_name, platform, views FROM top_clips WHERE campaign_id=%s ORDER BY views DESC LIMIT 10", (user['campaign_id'],))
    rows = cur.fetchall()
    cur.close()
    return jsonify({'success': True, 'leaderboard': rows})

@app.route('/api/dashboard/report')
def dashboard_report():
    if 'user_email' not in session:
        return redirect(url_for('client_login'))

    from datetime import datetime, date
    from io import BytesIO
    from flask import send_file
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm

    email = session['user_email']
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT u.full_name, u.email,
               c.campaign_id, c.campaign_name, c.budget_total,
               c.target_views, c.current_views, c.status,
               c.start_date, c.expected_end_date, c.cpm_rate
        FROM users u
        LEFT JOIN campaigns c ON u.campaign_id = c.campaign_id
        WHERE u.email = %s
    """, (email,))
    d = cur.fetchone()

    if d and d['expected_end_date']:
        expiry = d['expected_end_date']
        if isinstance(expiry, str):
            expiry = datetime.strptime(expiry, '%Y-%m-%d').date()
        from datetime import timedelta
        if date.today() > expiry + timedelta(days=365):
            cur.close()
            return jsonify({'error': 'Report expired (available for 1 year after completion)'}), 410

    if not d or not d['campaign_id']:
        cur.close()
        return jsonify({'error': 'No campaign found'}), 404

    cur.execute("SELECT views, recorded_at FROM views_history WHERE campaign_id=%s ORDER BY recorded_at ASC", (d['campaign_id'],))
    history = cur.fetchall()

    try:
        cur.execute("SELECT clipper_name, platform, views, url FROM clips WHERE campaign_id=%s ORDER BY views DESC LIMIT 10", (d['campaign_id'],))
        clips = cur.fetchall()
    except:
        clips = []
    cur.close()

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=20*mm, leftMargin=20*mm, topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()

    CYAN = colors.HexColor('#00CCCC')
    DARK = colors.HexColor('#0a0a14')
    MUTED = colors.HexColor('#8a9bb0')

    title_style = ParagraphStyle('Title', parent=styles['Normal'], fontSize=28, fontName='Helvetica-Bold', textColor=CYAN, spaceAfter=4)
    sub_style = ParagraphStyle('Sub', parent=styles['Normal'], fontSize=11, textColor=MUTED, spaceAfter=20)
    h2_style = ParagraphStyle('H2', parent=styles['Normal'], fontSize=14, fontName='Helvetica-Bold', textColor=colors.white, spaceAfter=10, spaceBefore=16)
    normal_style = ParagraphStyle('Normal2', parent=styles['Normal'], fontSize=10, textColor=MUTED)

    budget = float(d['budget_total'] or 0)
    cv = d['current_views'] or 0
    tv = d['target_views'] or 1
    pct = min(round((cv/tv)*100), 100)

    story = []
    story.append(Paragraph('Magnetise Media', title_style))
    story.append(Paragraph('Campaign Performance Report', sub_style))
    story.append(HRFlowable(width="100%", thickness=1, color=CYAN, spaceAfter=20))

    story.append(Paragraph('Campaign Summary', h2_style))
    data = [
        ['Campaign Name', str(d['campaign_name'])],
        ['Campaign ID', str(d['campaign_id'])],
        ['Client', str(d['full_name'])],
        ['Status', str(d['status'])],
        ['Start Date', str(d['start_date'])],
        ['End Date', str(d['expected_end_date'])],
        ['Total Views Delivered', f"{cv:,}"],
        ['Target Views', f"{tv:,}"],
        ['Completion', f"{pct}%"],
    ]
    t = Table(data, colWidths=[70*mm, 100*mm])
    t.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('TEXTCOLOR', (0,0), (0,-1), MUTED),
        ('TEXTCOLOR', (1,0), (1,-1), colors.white),
        ('FONTNAME', (1,0), (1,-1), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.HexColor('#111118'), colors.HexColor('#0d0d14')]),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#222233')),
    ]))
    story.append(t)

    story.append(Paragraph('Budget Breakdown', h2_style))
    ops_fee = round(budget * 0.30)
    view_budget = budget - ops_fee
    bdata = [
        ['Total Budget', f"${budget:,.0f}"],
        ['Operations Fee (30% — non-refundable)', f"${ops_fee:,.0f}"],
        ['View Guarantee (70%)', f"${view_budget:,.0f}"],
        ['Cost per 1,000 Views', f"${d['cpm_rate']:.2f}" if d['cpm_rate'] else 'N/A'],
    ]
    bt = Table(bdata, colWidths=[120*mm, 50*mm])
    bt.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('TEXTCOLOR', (0,0), (0,-1), MUTED),
        ('TEXTCOLOR', (1,0), (1,-1), colors.white),
        ('FONTNAME', (1,0), (1,-1), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.HexColor('#111118'), colors.HexColor('#0d0d14')]),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#222233')),
    ]))
    story.append(bt)

    if history:
        story.append(Paragraph('Views History', h2_style))
        hdata = [['Date', 'Views Recorded']]
        for h in history:
            hdata.append([str(h['recorded_at'])[:10], f"{h['views']:,}"])
        ht = Table(hdata, colWidths=[80*mm, 90*mm])
        ht.setStyle(TableStyle([
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('TEXTCOLOR', (0,0), (-1,0), CYAN),
            ('TEXTCOLOR', (0,1), (0,-1), MUTED),
            ('TEXTCOLOR', (1,1), (1,-1), colors.white),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#111118'), colors.HexColor('#0d0d14')]),
            ('TOPPADDING', (0,0), (-1,-1), 7),
            ('BOTTOMPADDING', (0,0), (-1,-1), 7),
            ('LEFTPADDING', (0,0), (-1,-1), 12),
            ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#222233')),
        ]))
        story.append(ht)

    if clips:
        story.append(Paragraph('Top Performing Clips', h2_style))
        cdata = [['#', 'Clipper', 'Platform', 'Views', 'URL']]
        for i, c in enumerate(clips, 1):
            cdata.append([str(i), str(c['clipper_name'] or '—'), str(c['platform'] or '—'), f"{(c['views'] or 0):,}", str(c['url'] or '—')[:40]])
        ct = Table(cdata, colWidths=[10*mm, 45*mm, 30*mm, 25*mm, 60*mm])
        ct.setStyle(TableStyle([
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('TEXTCOLOR', (0,0), (-1,0), CYAN),
            ('TEXTCOLOR', (0,1), (-1,-1), MUTED),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#111118'), colors.HexColor('#0d0d14')]),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#222233')),
        ]))
        story.append(ct)

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#222233')))
    story.append(Spacer(1, 8))
    story.append(Paragraph(f"Generated by Magnetise Media · magnetise.media · {date.today()}", ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=MUTED, alignment=1)))

    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"MagnetiseMedia_Report_{d['campaign_id']}.pdf", mimetype='application/pdf')

@app.route('/api/dashboard/views-history')
def dashboard_views_history():
    if 'user_email' not in session:
        return jsonify({'success': False}), 401
    email = session['user_email']
    days = request.args.get('days', None)
    cur = mysql.connection.cursor()
    cur.execute("SELECT campaign_id FROM users WHERE email=%s", (email,))
    user = cur.fetchone()
    if not user or not user['campaign_id']:
        return jsonify({'success': True, 'history': []})

    if days:
        cur.execute("""
            SELECT views, recorded_at FROM views_history
            WHERE campaign_id=%s AND recorded_at >= NOW() - INTERVAL %s DAY
            ORDER BY recorded_at ASC
        """, (user['campaign_id'], int(days)))
    else:
        cur.execute("""
            SELECT views, recorded_at FROM views_history
            WHERE campaign_id=%s ORDER BY recorded_at ASC
        """, (user['campaign_id'],))

    rows = cur.fetchall()
    cur.close()
    history = [{'views': r['views'], 'date': str(r['recorded_at'])} for r in rows]
    return jsonify({'success': True, 'history': history})


@app.route('/api/auth/change-password', methods=['POST'])
def api_change_password():
    if 'user_email' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    data = request.get_json()
    current_pw = data.get('current_password', '')
    new_pw = data.get('new_password', '')
    if not current_pw or not new_pw:
        return jsonify({'success': False, 'message': 'All fields required'})
    if len(new_pw) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'})
    email = session['user_email']
    cur = mysql.connection.cursor()
    cur.execute("SELECT password_hash FROM users WHERE email=%s", (email,))
    user = cur.fetchone()
    if not user or not pbkdf2_sha256.verify(current_pw, user['password_hash']):
        cur.close()
        return jsonify({'success': False, 'message': 'Current password is incorrect'})
    new_hash = pbkdf2_sha256.hash(new_pw)
    cur.execute("UPDATE users SET password_hash=%s WHERE email=%s", (new_hash, email))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    session.pop('user_email', None)
    return jsonify({'success': True})

@app.route('/api/auth/check')
def api_auth_check():
    if 'user_email' in session:
        return jsonify({'authenticated': True, 'email': session['user_email']})
    return jsonify({'authenticated': False}), 401

# ==========================================
# FORGOT PASSWORD
# ==========================================

@app.route('/forgot-password')
def forgot_password_page():
    return render_template('forgot_password.html')

@app.route('/api/auth/forgot-password', methods=['POST'])
@limiter.limit("2 per minute")
def api_forgot_password():
    data = request.get_json()
    email = data.get('email', '').strip().lower()

    cur = mysql.connection.cursor()
    cur.execute("SELECT full_name FROM users WHERE email=%s AND account_status='ACTIVE'", (email,))
    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({'success': False, 'message': 'No active account found.'})

    otp = str(random.randint(100000, 999999))

    reset_otp_store[email] = {
        'otp': otp,
        'expires': time.time() + 600
    }

    html_content = f"""
    <div style="font-family:Arial;padding:40px;background:#f4f4f4;">
        <div style="max-width:500px;margin:auto;background:white;padding:40px;border-radius:10px;">
            <h2 style="color:black;">Password Reset</h2>
            <p>Your password reset code:</p>
            <div style="font-size:34px;font-weight:800;letter-spacing:10px;background:black;color:white;padding:20px;border-radius:8px;text-align:center;">
                {otp}
            </div>
            <p style="margin-top:20px;color:#666;">Expires in 10 minutes.</p>
        </div>
    </div>
    """

    try:
        send_brevo_email(email, user['full_name'], "Reset Your Password", html_content)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    
@app.route('/api/auth/reset-password', methods=['POST'])
@limiter.limit("3 per minute")
def reset_password():
    data = request.get_json()

    email = data.get('email', '').strip().lower()
    otp = data.get('otp', '').strip()
    new_password = data.get('new_password', '').strip()

    if len(new_password) < 8:
        return jsonify({'success': False, 'message': 'Password too short'})

    record = reset_otp_store.get(email)

    if not record:
        return jsonify({'success': False, 'message': 'No reset request found'})

    if time.time() > record['expires']:
        reset_otp_store.pop(email, None)
        return jsonify({'success': False, 'message': 'OTP expired'})

    if record['otp'] != otp:
        return jsonify({'success': False, 'message': 'Invalid OTP'})

    password_hash = pbkdf2_sha256.hash(new_password)

    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET password_hash=%s WHERE email=%s", (password_hash, email))
    mysql.connection.commit()
    cur.close()

    reset_otp_store.pop(email, None)

    return jsonify({'success': True})


@app.route('/api/admin/set-cpm', methods=['POST'])
def admin_set_cpm():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    data = request.get_json()
    campaign_id = data.get('campaign_id')
    cpm_rate = data.get('cpm_rate')
    cur = mysql.connection.cursor()
    cur.execute("UPDATE campaigns SET cpm_rate=%s WHERE campaign_id=%s", (cpm_rate, campaign_id))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['Content-Security-Policy'] = "default-src 'self' https: data: blob: 'unsafe-inline' 'unsafe-eval'"
    return response

# ==========================================
# RUN
# ==========================================

if __name__ == '__main__':
    print("Magnetise Media Running on http://localhost:5000")
    create_tables()
    app.run(debug=False)