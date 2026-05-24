from flask import Flask, request, jsonify, session, redirect, render_template, url_for, send_file
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
from datetime import timedelta, datetime, date
import re
from urllib.parse import urlparse, unquote
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

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().strip("'\"")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "").strip().strip("'\"")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# ==========================================
# FIX 1: MySQL config uses individual env vars (no MYSQL_URL needed)
# ==========================================
app.config['MYSQL_HOST'] = os.getenv("MYSQL_HOST", "localhost")
app.config['MYSQL_USER'] = os.getenv("MYSQL_USER", "root")
app.config['MYSQL_PASSWORD'] = os.getenv("MYSQL_PASSWORD", "")
app.config['MYSQL_DB'] = os.getenv("MYSQL_DB", "magnetisemedia")
app.config['MYSQL_PORT'] = int(os.getenv("MYSQL_PORT", 3306))

# If a full connection URL is provided it wins — lets you paste ONE variable on Render
# instead of five. On Railway use MYSQL_PUBLIC_URL (the switchback.proxy.rlwy.net host),
# NOT the internal mysql.railway.internal URL, since Render connects from outside Railway.
_db_url = os.getenv("MYSQL_PUBLIC_URL") or os.getenv("MYSQL_URL") or os.getenv("DATABASE_URL")
if _db_url:
    _u = urlparse(_db_url)
    if _u.hostname: app.config['MYSQL_HOST'] = _u.hostname
    if _u.port:     app.config['MYSQL_PORT'] = _u.port
    if _u.username: app.config['MYSQL_USER'] = _u.username
    if _u.password: app.config['MYSQL_PASSWORD'] = unquote(_u.password)
    if _u.path and len(_u.path) > 1: app.config['MYSQL_DB'] = _u.path.lstrip('/')

app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)


# ==========================================
# FIX 2: OTP store moved to DB (no more memory loss on restart)
# All OTPs stored in otp_store table with expiry
# ==========================================

def create_tables():
    with app.app_context():
        try:
            cur = mysql.connection.cursor()

            # OTP store in DB — survives server restarts
            cur.execute("""
                CREATE TABLE IF NOT EXISTS otp_store (
                    email VARCHAR(255) PRIMARY KEY,
                    otp_code VARCHAR(6) NOT NULL,
                    full_name VARCHAR(255),
                    expires_at DATETIME NOT NULL,
                    attempts INT DEFAULT 0,
                    created_at DATETIME DEFAULT NOW()
                )
            """)

            # Reset OTP store in DB
            cur.execute("""
                CREATE TABLE IF NOT EXISTS reset_otp_store (
                    email VARCHAR(255) PRIMARY KEY,
                    otp_code VARCHAR(6) NOT NULL,
                    expires_at DATETIME NOT NULL,
                    attempts INT DEFAULT 0,
                    created_at DATETIME DEFAULT NOW()
                )
            """)

            # Views history
            cur.execute("""
                CREATE TABLE IF NOT EXISTS views_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    campaign_id VARCHAR(30),
                    views INT NOT NULL,
                    recorded_at DATETIME DEFAULT NOW(),
                    INDEX idx_campaign (campaign_id)
                )
            """)

            # FIX 3: top_clips table now actually created
            cur.execute("""
                CREATE TABLE IF NOT EXISTS top_clips (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    campaign_id VARCHAR(30) NOT NULL,
                    clipper_name VARCHAR(255),
                    platform VARCHAR(50),
                    views INT DEFAULT 0,
                    url VARCHAR(500),
                    youtube_video_id VARCHAR(50),
                    added_at DATETIME DEFAULT NOW(),
                    last_updated DATETIME DEFAULT NOW(),
                    INDEX idx_campaign (campaign_id)
                )
            """)

            # clips table (used by PDF report)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS clips (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    campaign_id VARCHAR(30) NOT NULL,
                    clipper_name VARCHAR(255),
                    platform VARCHAR(50),
                    views INT DEFAULT 0,
                    url VARCHAR(500),
                    youtube_video_id VARCHAR(50),
                    added_at DATETIME DEFAULT NOW(),
                    INDEX idx_campaign (campaign_id)
                )
            """)
            # Milestone emails tracker
            cur.execute("""
                CREATE TABLE IF NOT EXISTS milestone_emails_sent (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    campaign_id VARCHAR(30) NOT NULL,
                    milestone_pct INT NOT NULL,
                    sent_at DATETIME DEFAULT NOW(),
                    UNIQUE KEY unique_milestone (campaign_id, milestone_pct)
                )
            """)
            # password_reset_requests (kept for audit log)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS password_reset_requests (
                    email VARCHAR(255) PRIMARY KEY,
                    full_name VARCHAR(255),
                    status ENUM('PENDING','DONE') DEFAULT 'PENDING',
                    requested_at DATETIME
                )
            """)

            # Widen view columns INT -> BIGINT so large counts don't overflow (error 1264).
            # campaigns/users pre-exist so these are ALTERs; each is guarded so one failure
            # (e.g. table missing on a fresh DB) won't abort the rest.
            for _alter in (
                "ALTER TABLE campaigns MODIFY current_views BIGINT",
                "ALTER TABLE campaigns MODIFY target_views BIGINT",
                "ALTER TABLE views_history MODIFY views BIGINT NOT NULL",
                "ALTER TABLE top_clips MODIFY views BIGINT DEFAULT 0",
                "ALTER TABLE clips MODIFY views BIGINT DEFAULT 0",
            ):
                try:
                    cur.execute(_alter)
                except Exception as _ae:
                    print(f"skip alter: {_ae}")

            mysql.connection.commit()
            cur.close()
            print("All tables created successfully.")
        except Exception as e:
            print(f"Table init error: {e}")


# Run schema setup at import so the helper tables exist under gunicorn too
# (Render/Railway run `gunicorn app:app`, so __main__ never executes).
try:
    create_tables()
except Exception as _e:
    print(f"create_tables at startup failed: {_e}")


# ==========================================
# BREVO EMAIL HELPER
# ==========================================

def check_and_send_milestone_email(campaign_id, current_views, target_views, cur):
    """Fires a Brevo email when campaign hits 25/50/75/100% of target. Runs once per milestone."""
    if not target_views or target_views == 0:
        return
    pct = (current_views / target_views) * 100
    milestones = [100, 75, 50, 25]  # highest first
    hit = next((m for m in milestones if pct >= m), None)
    if not hit:
        return

    # Check if this milestone was already emailed
    cur.execute("""
        SELECT milestone_pct FROM milestone_emails_sent
        WHERE campaign_id=%s AND milestone_pct=%s
    """, (campaign_id, hit))
    if cur.fetchone():
        return  # Already sent

    # Get client info
    cur.execute("""
        SELECT u.full_name, u.email, c.campaign_name
        FROM users u JOIN campaigns c ON u.campaign_id=c.campaign_id
        WHERE c.campaign_id=%s
    """, (campaign_id,))
    info = cur.fetchone()
    if not info:
        return

    # Record milestone as sent
    cur.execute("""
        INSERT IGNORE INTO milestone_emails_sent (campaign_id, milestone_pct, sent_at)
        VALUES (%s, %s, NOW())
    """, (campaign_id, hit))

    emoji = {25:'🚀', 50:'⚡', 75:'🔥', 100:'🎉'}[hit]
    milestone_label = {25:'Halfway to launch!', 50:'Halfway there!', 75:'Almost done!', 100:'Target reached!'}[hit]

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:'Helvetica Neue',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:40px 16px;">
  <tr><td align="center">
    <table width="520" cellpadding="0" cellspacing="0" style="max-width:520px;width:100%;background:#fff;border-radius:8px;overflow:hidden;border:1px solid #e8e8e8;">
      <tr><td style="background:#0a0a0a;padding:32px 40px;text-align:center;">
        <div style="font-size:40px;margin-bottom:8px;">{emoji}</div>
        <div style="font-size:26px;font-weight:900;color:#fff;letter-spacing:-1px;">Magnetise Media</div>
        <div style="font-size:13px;color:#888;margin-top:4px;">Campaign Milestone</div>
      </td></tr>
      <tr><td style="padding:36px 40px;">
        <p style="font-size:16px;color:#1a1a1a;margin:0 0 12px;">Hey <strong>{info['full_name']}</strong>,</p>
        <p style="font-size:14px;color:#555;line-height:1.7;margin:0 0 24px;">
          Great news — your campaign <strong>{info['campaign_name']}</strong> just hit a milestone!
        </p>
        <div style="text-align:center;background:#0a0a0a;border-radius:12px;padding:28px;margin-bottom:28px;">
          <div style="font-size:56px;font-weight:900;color:#fff;">{hit}%</div>
          <div style="font-size:14px;color:#888;margin-top:4px;">{milestone_label}</div>
          <div style="font-size:13px;color:#666;margin-top:8px;">{current_views:,} of {target_views:,} views delivered</div>
        </div>
        <p style="font-size:14px;color:#555;text-align:center;margin:0 0 24px;">
          {'Your campaign has hit 100% of its target views! 🎉' if hit==100 else f'Keep an eye on your dashboard — we are pushing hard to hit the remaining {100-hit}%.'}
        </p>
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr><td align="center">
            <a href="https://magnetise.media/dashboard" style="display:inline-block;background:#0a0a0a;color:#fff;font-weight:700;font-size:14px;padding:13px 36px;border-radius:6px;text-decoration:none;">View Dashboard →</a>
          </td></tr>
        </table>
      </td></tr>
      <tr><td style="border-top:1px solid #eee;padding:20px 40px;text-align:center;background:#fafafa;">
        <p style="font-size:12px;color:#aaa;margin:0;">Magnetise Media · <a href="mailto:magnetisemedia.co@gmail.com" style="color:#555;text-decoration:none;">magnetisemedia.co@gmail.com</a></p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>"""

    try:
        send_brevo_email(info['email'], info['full_name'],
                         f"{emoji} Your campaign just hit {hit}% — {milestone_label}",
                         html)
    except Exception as e:
        print(f"Milestone email failed: {e}")

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
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({'success': False, 'message': 'No account found'})

    if user['account_status'] == 'PENDING':
        return jsonify({'success': False, 'message': 'Your account is pending approval. You will receive an email once approved.'})

    if user['account_status'] == 'REJECTED':
        return jsonify({'success': False, 'message': 'Your account was not approved. Contact support.'})

    if user['account_status'] not in ('ACTIVE', 'COMPLETED'):
        return jsonify({'success': False, 'message': 'Account not active'})

    if not user.get('password_hash') or not pbkdf2_sha256.verify(password, user['password_hash']):
        return jsonify({'success': False, 'message': 'Incorrect password'})

    session.permanent = True
    session['user_email'] = email
    return jsonify({'success': True})


# ==========================================
# OTP SIGNUP FLOW — Now uses DB, not memory
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

    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id FROM users WHERE email=%s", (email,))
    existing = cur.fetchone()
    if existing:
        cur.close()
        return jsonify({'success': False, 'message': 'An account with this email already exists.'})

    otp = str(random.randint(100000, 999999))
    expires_at = datetime.now() + timedelta(minutes=10)

    # FIX: Store OTP in DB instead of memory
    cur.execute("""
        INSERT INTO otp_store (email, otp_code, full_name, expires_at, attempts)
        VALUES (%s, %s, %s, %s, 0)
        ON DUPLICATE KEY UPDATE
            otp_code=VALUES(otp_code),
            full_name=VALUES(full_name),
            expires_at=VALUES(expires_at),
            attempts=0,
            created_at=NOW()
    """, (email, otp, name, expires_at))
    mysql.connection.commit()
    cur.close()

    html_content = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:'Helvetica Neue',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:40px 16px;">
  <tr><td align="center">
    <table width="520" cellpadding="0" cellspacing="0" style="max-width:520px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;border:1px solid #e8e8e8;">
      <tr><td style="background:#0a0a0a;padding:32px 40px;text-align:center;">
        <div style="font-size:26px;font-weight:900;color:#ffffff;letter-spacing:-1px;">Magnetise Media</div>
        <div style="font-size:13px;color:#888888;margin-top:4px;">Email Verification</div>
      </td></tr>
      <tr><td style="padding:36px 40px;">
        <p style="font-size:16px;color:#1a1a1a;margin:0 0 12px;">Hey <strong>{name}</strong>,</p>
        <p style="font-size:14px;color:#555555;line-height:1.7;margin:0 0 28px;">
          Use the verification code below to complete your Magnetise Media signup.
          This code expires in <strong>10 minutes</strong>.
        </p>
        <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
          <tr><td align="center">
            <div style="display:inline-block;background:#0a0a0a;color:#ffffff;font-size:36px;font-weight:900;letter-spacing:14px;padding:20px 36px;border-radius:8px;font-family:'Courier New',monospace;">{otp}</div>
          </td></tr>
        </table>
        <p style="font-size:13px;color:#999999;line-height:1.7;margin:0;text-align:center;">
          If you didn't request this, you can safely ignore this email.
        </p>
      </td></tr>
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
@limiter.limit("10 per hour")  # FIX: rate limit on OTP verify too
def verify_otp():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    otp = data.get('otp', '').strip()

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM otp_store WHERE email=%s", (email,))
    record = cur.fetchone()

    if not record:
        cur.close()
        return jsonify({'success': False, 'message': 'No verification code found. Please request a new one.'})

    # FIX: Max 5 attempts then invalidate
    if record['attempts'] >= 5:
        cur.execute("DELETE FROM otp_store WHERE email=%s", (email,))
        mysql.connection.commit()
        cur.close()
        return jsonify({'success': False, 'message': 'Too many attempts. Please request a new code.'})

    if datetime.now() > record['expires_at']:
        cur.execute("DELETE FROM otp_store WHERE email=%s", (email,))
        mysql.connection.commit()
        cur.close()
        return jsonify({'success': False, 'message': 'Code has expired. Please request a new one.'})

    if record['otp_code'] != otp:
        # Increment attempt count
        cur.execute("UPDATE otp_store SET attempts=attempts+1 WHERE email=%s", (email,))
        mysql.connection.commit()
        attempts_left = 4 - record['attempts']
        cur.close()
        return jsonify({'success': False, 'message': f'Incorrect code. {attempts_left} attempt(s) remaining.'})

    # OTP valid — create user
    name = record['full_name']
    cur.execute("DELETE FROM otp_store WHERE email=%s", (email,))

    try:
        cur.execute(
            "INSERT INTO users (user_id, full_name, email, account_status) VALUES (%s,%s,%s,'PENDING')",
            (str(uuid.uuid4()), name, email)
        )
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        cur.close()
        return jsonify({'success': False, 'message': 'Account creation failed. Email may already exist.'})

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
        SELECT u.user_id, u.full_name, u.email, u.account_status, u.rejection_reason,
               c.campaign_id, c.campaign_name, c.current_views, c.target_views,
               c.budget_total, c.cpm_rate, c.status AS campaign_status,
               c.start_date, c.expected_end_date, c.login_email_sent_at
        FROM users u
        LEFT JOIN campaigns c ON u.campaign_id = c.campaign_id
        ORDER BY u.created_at DESC
    """)
    clients = cur.fetchall()
    cur.close()
    for c in clients:
        c['email_sent'] = bool(c.get('login_email_sent_at'))
        c['login_email_sent_at'] = str(c['login_email_sent_at']) if c['login_email_sent_at'] else None
        if c.get('start_date'): c['start_date'] = str(c['start_date'])
        if c.get('expected_end_date'): c['expected_end_date'] = str(c['expected_end_date'])
        if c.get('budget_total') is not None: c['budget_total'] = float(c['budget_total'])
        if c.get('cpm_rate') is not None: c['cpm_rate'] = float(c['cpm_rate'])
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

    # Short ID (15 chars) so it fits the existing campaigns.campaign_id column;
    # random hex suffix prevents collisions. e.g. CX-260524F3A9C1
    import secrets
    campaign_id = 'CX-' + datetime.now().strftime('%y%m%d') + secrets.token_hex(3).upper()

    cur = mysql.connection.cursor()
    try:
        cur.execute("""INSERT INTO campaigns
                       (campaign_id, client_email, campaign_name, budget_total, target_views, start_date, expected_end_date, status, created_by)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,'ACTIVE',%s)""",
                    (campaign_id, client_email, campaign_name, budget, views, start, end, session['admin_email']))
        # Only set password if this is first campaign (no existing hash)
        cur.execute("SELECT password_hash FROM users WHERE email=%s", (client_email,))
        existing = cur.fetchone()
        if existing and existing['password_hash']:
            # Repeat client — keep existing password, just update active campaign
            cur.execute("UPDATE users SET account_status='ACTIVE', campaign_id=%s WHERE email=%s",
                        (campaign_id, client_email))
        else:
            # First campaign — set password
            cur.execute("UPDATE users SET account_status='ACTIVE', password_hash=%s, campaign_id=%s WHERE email=%s",
                        (password_hash, campaign_id, client_email))
        mysql.connection.commit()
    except Exception as e:
        mysql.connection.rollback()
        cur.close()
        return jsonify({'success': False, 'message': f'Database error: {str(e)}'}), 400
    cur.close()
    return jsonify({'success': True, 'campaign_id': campaign_id, 'campaign_name': campaign_name})

@app.route('/api/admin/update-campaign', methods=['POST'])
def admin_update_campaign():
    """Edit every campaign field the client sees. Only fields present in the request are changed."""
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    data = request.get_json()
    campaign_id = data.get('campaign_id')
    if not campaign_id:
        return jsonify({'success': False, 'message': 'campaign_id required'}), 400

    cur = mysql.connection.cursor()
    cur.execute("SELECT target_views, current_views FROM campaigns WHERE campaign_id=%s", (campaign_id,))
    existing = cur.fetchone()
    if not existing:
        cur.close()
        return jsonify({'success': False, 'message': 'Campaign not found'}), 404

    # Column -> incoming value. Keys are a fixed whitelist (never user-supplied), values are parameterized.
    candidates = {
        'campaign_name': data.get('campaign_name'),
        'budget_total': data.get('budget_total'),
        'target_views': data.get('target_views'),
        'current_views': data.get('current_views'),
        'cpm_rate': data.get('cpm_rate'),
        'start_date': data.get('start_date'),
        'expected_end_date': data.get('expected_end_date'),
    }
    set_clauses, values = [], []
    for col, val in candidates.items():
        if val is not None and val != '':
            set_clauses.append(f"{col}=%s")
            values.append(val)

    new_status = data.get('status')
    if new_status in ('ACTIVE', 'COMPLETED'):
        set_clauses.append("status=%s")
        values.append(new_status)

    if set_clauses:
        values.append(campaign_id)
        cur.execute(f"UPDATE campaigns SET {', '.join(set_clauses)} WHERE campaign_id=%s", tuple(values))

    # Keep the user's account_status in sync with the campaign status
    if new_status in ('ACTIVE', 'COMPLETED'):
        cur.execute("UPDATE users SET account_status=%s WHERE campaign_id=%s", (new_status, campaign_id))

    # If views actually changed, log a history point and run the milestone email check
    new_views = candidates['current_views']
    if new_views is not None and str(new_views) != '':
        try:
            nv = int(new_views)
            if nv != (existing['current_views'] or 0):
                cur.execute("INSERT INTO views_history (campaign_id, views) VALUES (%s, %s)", (campaign_id, nv))
                tv = candidates['target_views'] if candidates['target_views'] not in (None, '') else existing['target_views']
                if tv:
                    check_and_send_milestone_email(campaign_id, nv, int(tv), cur)
        except (ValueError, TypeError):
            pass

    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

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
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:'Helvetica Neue',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:40px 16px;">
  <tr><td align="center">
    <table width="520" cellpadding="0" cellspacing="0" style="max-width:520px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;border:1px solid #e8e8e8;">
      <tr><td style="background:#0a0a0a;padding:32px 40px;text-align:center;">
        <div style="font-size:26px;font-weight:900;color:#ffffff;letter-spacing:-1px;">Magnetise Media</div>
        <div style="font-size:13px;color:#888888;margin-top:4px;">Campaign Dashboard Access</div>
      </td></tr>
      <tr><td style="padding:36px 40px;">
        <p style="font-size:16px;color:#1a1a1a;margin:0 0 12px;">Hey <strong>{info['full_name']}</strong>,</p>
        <p style="font-size:14px;color:#555555;line-height:1.7;margin:0 0 28px;">Your campaign is live. Below are your login credentials.</p>
        <div style="font-size:11px;font-weight:700;color:#999;letter-spacing:0.08em;text-transform:uppercase;margin-bottom:8px;">Campaign Details</div>
        <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:20px;border:1px solid #e8e8e8;border-radius:6px;overflow:hidden;">
          <tr style="background:#f9f9f9;"><td style="padding:10px 16px;font-size:13px;color:#888;">Campaign</td><td style="padding:10px 16px;font-size:13px;color:#1a1a1a;font-weight:600;text-align:right;">{info['campaign_name']}</td></tr>
          <tr><td style="padding:10px 16px;font-size:13px;color:#888;border-top:1px solid #f0f0f0;">Campaign ID</td><td style="padding:10px 16px;font-size:13px;font-weight:700;text-align:right;border-top:1px solid #f0f0f0;font-family:'Courier New',monospace;">{info['campaign_id']}</td></tr>
          <tr style="background:#f9f9f9;"><td style="padding:10px 16px;font-size:13px;color:#888;border-top:1px solid #f0f0f0;">Budget</td><td style="padding:10px 16px;font-size:13px;font-weight:600;text-align:right;border-top:1px solid #f0f0f0;">${info['budget_total']:,.0f}</td></tr>
          <tr><td style="padding:10px 16px;font-size:13px;color:#888;border-top:1px solid #f0f0f0;">Target Views</td><td style="padding:10px 16px;font-size:13px;font-weight:600;text-align:right;border-top:1px solid #f0f0f0;">{info['target_views']:,}</td></tr>
          <tr style="background:#f9f9f9;"><td style="padding:10px 16px;font-size:13px;color:#888;border-top:1px solid #f0f0f0;">Duration</td><td style="padding:10px 16px;font-size:13px;font-weight:600;text-align:right;border-top:1px solid #f0f0f0;">{str(info['start_date'])} → {str(info['expected_end_date'])}</td></tr>
        </table>
        <div style="font-size:11px;font-weight:700;color:#999;letter-spacing:0.08em;text-transform:uppercase;margin-bottom:8px;">Login Credentials</div>
        <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:32px;border:1px solid #e8e8e8;border-radius:6px;overflow:hidden;">
          <tr style="background:#f9f9f9;"><td style="padding:10px 16px;font-size:13px;color:#888;">Email</td><td style="padding:10px 16px;font-size:13px;font-weight:600;text-align:right;">{info['email']}</td></tr>
          <tr><td style="padding:10px 16px;font-size:13px;color:#888;border-top:1px solid #f0f0f0;">Password</td><td style="padding:10px 16px;text-align:right;border-top:1px solid #f0f0f0;"><span style="background:#f0f0f0;font-family:'Courier New',monospace;font-size:15px;font-weight:700;padding:4px 12px;border-radius:4px;">{client_password}</span></td></tr>
        </table>
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr><td align="center">
            <a href="https://magnetise.media/client-login" style="display:inline-block;background:#0a0a0a;color:#ffffff;font-weight:700;font-size:15px;padding:14px 44px;border-radius:6px;text-decoration:none;">Login to Dashboard →</a>
          </td></tr>
        </table>
      </td></tr>
      <tr><td style="border-top:1px solid #eee;padding:20px 40px;text-align:center;background:#fafafa;">
        <p style="font-size:12px;color:#aaa;margin:0;">Magnetise Media · <a href="mailto:magnetisemedia.co@gmail.com" style="color:#555;text-decoration:none;">magnetisemedia.co@gmail.com</a></p>
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
    # FIX: Set user status to COMPLETED not ACTIVE
    cur.execute("UPDATE users SET account_status='COMPLETED' WHERE campaign_id=%s", (campaign_id,))
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
    # Get target for milestone check
    cur.execute("SELECT target_views FROM campaigns WHERE campaign_id=%s", (campaign_id,))
    row = cur.fetchone()
    if row:
        check_and_send_milestone_email(campaign_id, current_views, row['target_views'], cur)
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

# FIX: New route — Admin adds clips via UI (no more manual DB inserts)
@app.route('/api/admin/add-clip', methods=['POST'])
def admin_add_clip():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    data = request.get_json()
    campaign_id = data.get('campaign_id')
    clipper_name = data.get('clipper_name', '')
    platform = data.get('platform', '')
    views = data.get('views', 0)
    url = data.get('url', '')

    if not campaign_id or not clipper_name or not platform:
        return jsonify({'success': False, 'message': 'campaign_id, clipper_name and platform are required'})

    # Extract YouTube video ID from URL if YouTube
    yt_video_id = None
    if 'youtube.com' in url or 'youtu.be' in url:
        import re as _re
        match = _re.search(r'(?:v=|youtu\.be/|shorts/)([A-Za-z0-9_-]{11})', url)
        if match:
            yt_video_id = match.group(1)

    cur = mysql.connection.cursor()
    # Insert into both top_clips and clips (clips is used by PDF)
    cur.execute("""
        INSERT INTO top_clips (campaign_id, clipper_name, platform, views, url, youtube_video_id)
        VALUES (%s,%s,%s,%s,%s,%s)
    """, (campaign_id, clipper_name, platform, views, url, yt_video_id))
    cur.execute("""
        INSERT INTO clips (campaign_id, clipper_name, platform, views, url, youtube_video_id)
        VALUES (%s,%s,%s,%s,%s,%s)
    """, (campaign_id, clipper_name, platform, views, url, yt_video_id))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

# New route — Get all clips for a campaign (admin view)
@app.route('/api/admin/clips/<campaign_id>')
def admin_get_clips(campaign_id):
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT id, clipper_name, platform, views, url, added_at
        FROM top_clips WHERE campaign_id=%s ORDER BY views DESC
    """, (campaign_id,))
    clips = cur.fetchall()
    cur.close()
    for c in clips:
        c['added_at'] = str(c['added_at'])
    return jsonify({'success': True, 'clips': clips})

# New route — Delete a clip
@app.route('/api/admin/delete-clip', methods=['POST'])
def admin_delete_clip():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    data = request.get_json()
    clip_id = data.get('clip_id')
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM top_clips WHERE id=%s", (clip_id,))
    cur.execute("DELETE FROM clips WHERE id=%s", (clip_id,))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

# Edit an existing clip (top_clips is what the client dashboard reads; clips is mirrored for the PDF)
@app.route('/api/admin/update-clip', methods=['POST'])
def admin_update_clip():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    data = request.get_json()
    clip_id = data.get('clip_id')
    if not clip_id:
        return jsonify({'success': False, 'message': 'clip_id required'}), 400
    clipper_name = data.get('clipper_name', '')
    platform = data.get('platform', '')
    views = data.get('views', 0)
    url = data.get('url', '')

    yt_video_id = None
    if 'youtube.com' in url or 'youtu.be' in url:
        match = re.search(r'(?:v=|youtu\.be/|shorts/)([A-Za-z0-9_-]{11})', url)
        if match:
            yt_video_id = match.group(1)

    cur = mysql.connection.cursor()
    cur.execute("SELECT campaign_id, clipper_name, platform FROM top_clips WHERE id=%s", (clip_id,))
    row = cur.fetchone()
    if not row:
        cur.close()
        return jsonify({'success': False, 'message': 'Clip not found'}), 404
    cur.execute("""
        UPDATE top_clips SET clipper_name=%s, platform=%s, views=%s, url=%s, youtube_video_id=%s, last_updated=NOW()
        WHERE id=%s
    """, (clipper_name, platform, views, url, yt_video_id, clip_id))
    # Best-effort mirror onto the clips table, matched by the original clipper/platform within the campaign
    cur.execute("""
        UPDATE clips SET clipper_name=%s, platform=%s, views=%s, url=%s, youtube_video_id=%s
        WHERE campaign_id=%s AND clipper_name=%s AND platform=%s
    """, (clipper_name, platform, views, url, yt_video_id, row['campaign_id'], row['clipper_name'], row['platform']))

    # Keep the campaign's total views in sync with the clip totals
    cur.execute("SELECT SUM(views) as total FROM top_clips WHERE campaign_id=%s", (row['campaign_id'],))
    total = int((cur.fetchone() or {}).get('total') or 0)
    cur.execute("UPDATE campaigns SET current_views=%s WHERE campaign_id=%s", (total, row['campaign_id']))
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
            UPDATE users SET account_status='PENDING', rejection_reason=NULL WHERE user_id=%s
        """, (user_id,))
        mysql.connection.commit()
        cur.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/admin/delete-client', methods=['POST'])
def delete_client():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    data = request.get_json()
    user_id = data.get('user_id')
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT campaign_id FROM users WHERE user_id=%s", (user_id,))
        user = cur.fetchone()
        if user and user.get('campaign_id'):
            campaign_id = user['campaign_id']
            cur.execute("DELETE FROM views_history WHERE campaign_id=%s", (campaign_id,))
            cur.execute("DELETE FROM top_clips WHERE campaign_id=%s", (campaign_id,))
            cur.execute("DELETE FROM clips WHERE campaign_id=%s", (campaign_id,))
            cur.execute("DELETE FROM campaigns WHERE campaign_id=%s", (campaign_id,))
        cur.execute("DELETE FROM users WHERE user_id=%s", (user_id,))
        mysql.connection.commit()
        cur.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/admin/reset-client-password', methods=['POST'])
def admin_reset_client_password():
    """Admin override of a client's password (client can also self-serve via change/forgot)."""
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    data = request.get_json()
    email = (data.get('email') or '').strip().lower()
    new_password = data.get('new_password', '')
    if not email or not new_password:
        return jsonify({'success': False, 'message': 'Email and new password required'}), 400
    if len(new_password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id FROM users WHERE email=%s", (email,))
    if not cur.fetchone():
        cur.close()
        return jsonify({'success': False, 'message': 'Client not found'}), 404
    cur.execute("UPDATE users SET password_hash=%s WHERE email=%s",
                (pbkdf2_sha256.hash(new_password), email))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

@app.route('/api/admin/impersonate', methods=['POST'])
def admin_impersonate():
    """'View as client' — load the client's real dashboard in this session. Admin stays logged in."""
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    data = request.get_json()
    email = (data.get('email') or '').strip().lower()
    if not email:
        return jsonify({'success': False, 'message': 'Email required'}), 400
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id FROM users WHERE email=%s", (email,))
    if not cur.fetchone():
        cur.close()
        return jsonify({'success': False, 'message': 'Client not found'}), 404
    cur.close()
    session['user_email'] = email
    session['impersonator_email'] = session.get('admin_email', 'admin')
    return jsonify({'success': True, 'redirect': '/dashboard'})

@app.route('/admin/stop-impersonate')
def admin_stop_impersonate():
    """Exit 'view as client' and return to the admin dashboard."""
    if not session.get('admin_logged_in'):
        return redirect('/admin')
    session.pop('user_email', None)
    session.pop('impersonator_email', None)
    return redirect('/admin/dashboard')

# ==========================================
# BOT API — Discord bot calls these routes
# Auth: X-Bot-Secret header must match BOT_SECRET_KEY in .env
# ==========================================

BOT_SECRET = os.getenv("BOT_SECRET_KEY", "")

def bot_auth():
    """Returns True if request has valid bot secret header."""
    return request.headers.get("X-Bot-Secret") == BOT_SECRET and BOT_SECRET != ""


@app.route('/api/bot/submit-clip', methods=['POST'])
def bot_submit_clip():
    """Discord bot calls this when clipper runs !submit command."""
    if not bot_auth():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.get_json()
    campaign_id  = data.get('campaign_id', '').strip()
    clipper_name = data.get('clipper_name', '').strip()
    platform     = data.get('platform', '').strip()      # TikTok / YouTube / Reels / Shorts
    views        = int(data.get('views', 0))
    url          = data.get('url', '').strip()

    if not campaign_id or not clipper_name or not platform:
        return jsonify({'success': False, 'message': 'campaign_id, clipper_name, platform required'}), 400

    # Extract YouTube video ID from URL
    yt_video_id = None
    if 'youtube.com' in url or 'youtu.be' in url:
        match = re.search(r'(?:v=|youtu\.be/|shorts/)([A-Za-z0-9_-]{11})', url)
        if match:
            yt_video_id = match.group(1)

    cur = mysql.connection.cursor()

    # Check campaign exists
    cur.execute("SELECT campaign_id FROM campaigns WHERE campaign_id=%s", (campaign_id,))
    if not cur.fetchone():
        cur.close()
        return jsonify({'success': False, 'message': 'Campaign not found'}), 404

    # Insert clip into both tables
    cur.execute("""
        INSERT INTO top_clips (campaign_id, clipper_name, platform, views, url, youtube_video_id)
        VALUES (%s,%s,%s,%s,%s,%s)
    """, (campaign_id, clipper_name, platform, views, url, yt_video_id))
    cur.execute("""
        INSERT INTO clips (campaign_id, clipper_name, platform, views, url, youtube_video_id)
        VALUES (%s,%s,%s,%s,%s,%s)
    """, (campaign_id, clipper_name, platform, views, url, yt_video_id))

    # Auto-sync campaign total views from sum of all clips
    cur.execute("SELECT SUM(views) as total FROM top_clips WHERE campaign_id=%s", (campaign_id,))
    result = cur.fetchone()
    total_views = int(result['total'] or 0)
    cur.execute("UPDATE campaigns SET current_views=%s WHERE campaign_id=%s", (total_views, campaign_id))
    cur.execute("INSERT INTO views_history (campaign_id, views) VALUES (%s,%s)", (campaign_id, total_views))
    cur.execute("SELECT target_views FROM campaigns WHERE campaign_id=%s", (campaign_id,))
    trow = cur.fetchone()
    if trow:
        check_and_send_milestone_email(campaign_id, total_views, trow['target_views'], cur)

    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True, 'total_views': total_views})


@app.route('/api/bot/update-views', methods=['POST'])
def bot_update_views():
    """YouTube cron calls this to update view counts on existing clips."""
    if not bot_auth():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.get_json()
    # Expects: [{"youtube_video_id": "abc123", "views": 50000}, ...]
    updates = data.get('updates', [])

    if not updates:
        return jsonify({'success': False, 'message': 'No updates provided'}), 400

    cur = mysql.connection.cursor()
    affected_campaigns = set()

    for item in updates:
        vid_id = item.get('youtube_video_id')
        new_views = int(item.get('views', 0))
        if not vid_id:
            continue
        cur.execute("""
            UPDATE top_clips SET views=%s, last_updated=NOW()
            WHERE youtube_video_id=%s
        """, (new_views, vid_id))
        cur.execute("""
            UPDATE clips SET views=%s
            WHERE youtube_video_id=%s
        """, (new_views, vid_id))
        # Track which campaigns were touched
        cur.execute("SELECT DISTINCT campaign_id FROM top_clips WHERE youtube_video_id=%s", (vid_id,))
        for row in cur.fetchall():
            affected_campaigns.add(row['campaign_id'])

    # Re-sync totals for every affected campaign
    for cid in affected_campaigns:
        cur.execute("SELECT SUM(views) as total FROM top_clips WHERE campaign_id=%s", (cid,))
        result = cur.fetchone()
        total_views = int(result['total'] or 0)
        cur.execute("UPDATE campaigns SET current_views=%s WHERE campaign_id=%s", (total_views, cid))
        cur.execute("INSERT INTO views_history (campaign_id, views) VALUES (%s,%s)", (cid, total_views))
        cur.execute("SELECT target_views FROM campaigns WHERE campaign_id=%s", (cid,))
        trow = cur.fetchone()
        if trow:
            check_and_send_milestone_email(cid, total_views, trow['target_views'], cur)

    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True, 'campaigns_updated': list(affected_campaigns)})

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


# ==========================================
# CLIENT DASHBOARD DATA
# FIX: rejection_reason now returned so client sees why they were rejected
# ==========================================

@app.route('/api/dashboard/data')
def dashboard_data():
    if 'user_email' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401

    email = session['user_email']
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT u.full_name, u.email, u.account_status, u.rejection_reason,
            c.campaign_id, c.campaign_name, c.budget_total,
            c.target_views, c.current_views, c.status,
            c.start_date, c.expected_end_date, c.cpm_rate
        FROM users u
        LEFT JOIN campaigns c ON u.campaign_id = c.campaign_id
        WHERE u.email = %s
    """, (email,))
    row = cur.fetchone()
    # Also get full campaign history for account page
    cur.execute("""
        SELECT campaign_id, campaign_name, budget_total, target_views,
               current_views, status, start_date, expected_end_date, cpm_rate
        FROM campaigns WHERE client_email=%s ORDER BY created_at DESC
    """, (email,))
    all_campaigns = cur.fetchall()
    for c in all_campaigns:
        if c.get('start_date'): c['start_date'] = str(c['start_date'])
        if c.get('expected_end_date'): c['expected_end_date'] = str(c['expected_end_date'])
    cur.close()

    if not row:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    row['all_campaigns'] = all_campaigns

    if row.get('start_date'):
        row['start_date'] = str(row['start_date'])
    if row.get('expected_end_date'):
        row['expected_end_date'] = str(row['expected_end_date'])

    # Auto-calculate days remaining and budget left
    if row.get('expected_end_date'):
        end_date = datetime.strptime(row['expected_end_date'], '%Y-%m-%d').date()
        days_left = max((end_date - date.today()).days, 0)
        row['days_remaining'] = days_left
    else:
        row['days_remaining'] = None

    if row.get('budget_total') and row.get('cpm_rate') and row.get('current_views'):
        views_cost = (row['current_views'] / 1000) * float(row['cpm_rate'])
        row['budget_spent'] = round(views_cost, 2)
        row['budget_remaining'] = round(float(row['budget_total']) - views_cost, 2)
    else:
        row['budget_spent'] = 0
        row['budget_remaining'] = float(row.get('budget_total') or 0)

    row['impersonating'] = bool(session.get('impersonator_email'))
    row['impersonator_email'] = session.get('impersonator_email')

    return jsonify({'success': True, 'data': row})

@app.route('/api/dashboard/top-clips')
def dashboard_top_clips():
    if 'user_email' not in session:
        return jsonify({'success': False}), 401
    cur = mysql.connection.cursor()
    cur.execute("SELECT campaign_id FROM users WHERE email=%s", (session['user_email'],))
    user = cur.fetchone()
    if not user or not user['campaign_id']:
        cur.close()
        return jsonify({'success': True, 'clips': []})
    cur.execute("""
        SELECT clipper_name, platform, views, url
        FROM top_clips WHERE campaign_id=%s AND views>=10000
        ORDER BY views DESC
    """, (user['campaign_id'],))
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
        cur.close()
        return jsonify({'success': True, 'leaderboard': []})
    cur.execute("""
        SELECT clipper_name, platform, views
        FROM top_clips WHERE campaign_id=%s
        ORDER BY views DESC LIMIT 10
    """, (user['campaign_id'],))
    rows = cur.fetchall()
    cur.close()
    return jsonify({'success': True, 'leaderboard': rows})

@app.route('/api/dashboard/platform-breakdown')
def dashboard_platform_breakdown():
    if 'user_email' not in session:
        return jsonify({'success': False}), 401
    cur = mysql.connection.cursor()
    cur.execute("SELECT campaign_id FROM users WHERE email=%s", (session['user_email'],))
    user = cur.fetchone()
    if not user or not user['campaign_id']:
        cur.close()
        return jsonify({'success': True, 'breakdown': []})
    cur.execute("""
        SELECT platform, SUM(views) as total_views, COUNT(*) as clip_count
        FROM top_clips WHERE campaign_id=%s
        GROUP BY platform ORDER BY total_views DESC
    """, (user['campaign_id'],))
    rows = cur.fetchall()
    cur.close()
    return jsonify({'success': True, 'breakdown': rows})

@app.route('/api/dashboard/weekly-milestones')
def dashboard_weekly_milestones():
    if 'user_email' not in session:
        return jsonify({'success': False}), 401
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT c.start_date, c.expected_end_date, c.target_views
        FROM users u JOIN campaigns c ON u.campaign_id=c.campaign_id
        WHERE u.email=%s
    """, (session['user_email'],))
    camp = cur.fetchone()
    if not camp or not camp['start_date']:
        cur.close()
        return jsonify({'success': True, 'weeks': []})

    start = camp['start_date']
    end   = camp['expected_end_date']
    target_views = camp['target_views'] or 0

    from datetime import timedelta
    total_days = max((end - start).days, 1)
    total_weeks = max(total_days // 7, 1)
    weekly_target = target_views // total_weeks

    weeks = []
    for w in range(total_weeks):
        week_start = start + timedelta(weeks=w)
        week_end   = week_start + timedelta(days=6)
        # Get max views recorded in this week window
        cur.execute("""
            SELECT MAX(views) as peak FROM views_history
            WHERE campaign_id=(SELECT campaign_id FROM users WHERE email=%s)
            AND recorded_at BETWEEN %s AND %s
        """, (session['user_email'], week_start, week_end))
        row = cur.fetchone()
        peak = row['peak'] or 0
        # Get start-of-week baseline
        cur.execute("""
            SELECT MAX(views) as base FROM views_history
            WHERE campaign_id=(SELECT campaign_id FROM users WHERE email=%s)
            AND recorded_at < %s
        """, (session['user_email'], week_start))
        base_row = cur.fetchone()
        baseline = base_row['base'] or 0
        delivered = max(peak - baseline, 0)
        weeks.append({
            'week': w + 1,
            'target': weekly_target,
            'delivered': delivered,
            'hit': delivered >= weekly_target
        })

    cur.close()
    return jsonify({'success': True, 'weeks': weeks})

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
        cur.close()
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


# ==========================================
# PDF REPORT
# ==========================================

@app.route('/api/dashboard/report')
def dashboard_report():
    if 'user_email' not in session:
        return redirect(url_for('client_login'))

    from io import BytesIO
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

    if not d or not d['campaign_id']:
        cur.close()
        return jsonify({'error': 'No campaign found'}), 404

    if d and d['expected_end_date']:
        expiry = d['expected_end_date']
        if isinstance(expiry, str):
            expiry = datetime.strptime(expiry, '%Y-%m-%d').date()
        if date.today() > expiry + timedelta(days=365):
            cur.close()
            return jsonify({'error': 'Report expired (available for 1 year after completion)'}), 410

    cur.execute("SELECT views, recorded_at FROM views_history WHERE campaign_id=%s ORDER BY recorded_at ASC", (d['campaign_id'],))
    history = cur.fetchall()

    cur.execute("SELECT clipper_name, platform, views, url FROM clips WHERE campaign_id=%s ORDER BY views DESC LIMIT 10", (d['campaign_id'],))
    clips = cur.fetchall()
    cur.close()

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=20*mm, leftMargin=20*mm, topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()

    DARK = colors.HexColor('#0a0a14')
    MUTED = colors.HexColor('#8a9bb0')
    ACCENT = colors.HexColor('#333333')

    title_style = ParagraphStyle('Title', parent=styles['Normal'], fontSize=28, fontName='Helvetica-Bold', textColor=ACCENT, spaceAfter=4)
    sub_style = ParagraphStyle('Sub', parent=styles['Normal'], fontSize=11, textColor=MUTED, spaceAfter=20)
    h2_style = ParagraphStyle('H2', parent=styles['Normal'], fontSize=14, fontName='Helvetica-Bold', textColor=colors.black, spaceAfter=10, spaceBefore=16)
    normal_style = ParagraphStyle('Normal2', parent=styles['Normal'], fontSize=10, textColor=MUTED)

    budget = float(d['budget_total'] or 0)
    cv = d['current_views'] or 0
    tv = d['target_views'] or 1
    pct = min(round((cv/tv)*100), 100)

    story = []
    story.append(Paragraph('Magnetise Media', title_style))
    story.append(Paragraph('Campaign Performance Report', sub_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.black, spaceAfter=20))

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
        ('TEXTCOLOR', (1,0), (1,-1), colors.black),
        ('FONTNAME', (1,0), (1,-1), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.HexColor('#f9f9f9'), colors.white]),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#e0e0e0')),
    ]))
    story.append(t)

    story.append(Paragraph('Budget Breakdown', h2_style))
    ops_fee = round(budget * 0.30)
    view_budget = budget - ops_fee
    bdata = [
        ['Total Budget', f"${budget:,.0f}"],
        ['Operations Fee (30%)', f"${ops_fee:,.0f}"],
        ['View Guarantee (70%)', f"${view_budget:,.0f}"],
        ['Cost per 1,000 Views (CPM)', f"${d['cpm_rate']:.2f}" if d['cpm_rate'] else 'N/A'],
    ]
    bt = Table(bdata, colWidths=[120*mm, 50*mm])
    bt.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('TEXTCOLOR', (0,0), (0,-1), MUTED),
        ('TEXTCOLOR', (1,0), (1,-1), colors.black),
        ('FONTNAME', (1,0), (1,-1), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.HexColor('#f9f9f9'), colors.white]),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#e0e0e0')),
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
            ('TEXTCOLOR', (0,0), (-1,0), colors.black),
            ('TEXTCOLOR', (0,1), (0,-1), MUTED),
            ('TEXTCOLOR', (1,1), (1,-1), colors.black),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f9f9f9'), colors.white]),
            ('TOPPADDING', (0,0), (-1,-1), 7),
            ('BOTTOMPADDING', (0,0), (-1,-1), 7),
            ('LEFTPADDING', (0,0), (-1,-1), 12),
            ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#e0e0e0')),
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
            ('TEXTCOLOR', (0,0), (-1,0), colors.black),
            ('TEXTCOLOR', (0,1), (-1,-1), MUTED),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f9f9f9'), colors.white]),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#e0e0e0')),
        ]))
        story.append(ct)

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e0e0e0')))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        f"Generated by Magnetise Media · magnetise.media · {date.today()}",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=MUTED, alignment=1)
    ))

    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"MagnetiseMedia_Report_{d['campaign_id']}.pdf", mimetype='application/pdf')
@app.route('/api/admin/invoice/<campaign_id>')
def admin_invoice(campaign_id):
    if not session.get('admin_logged_in'):
        return redirect('/admin')

    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT u.full_name, u.email, c.campaign_id, c.campaign_name,
               c.budget_total, c.target_views, c.start_date, c.expected_end_date,
               c.created_by, c.status
        FROM campaigns c JOIN users u ON c.client_email=u.email
        WHERE c.campaign_id=%s
    """, (campaign_id,))
    d = cur.fetchone()
    cur.close()

    if not d:
        return jsonify({'error': 'Campaign not found'}), 404

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            rightMargin=20*mm, leftMargin=20*mm,
                            topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    MUTED = colors.HexColor('#888888')
    DARK  = colors.HexColor('#0a0a0a')

    story = []
    story.append(Paragraph('INVOICE', ParagraphStyle('INV', fontSize=32, fontName='Helvetica-Bold', textColor=DARK, spaceAfter=4)))
    story.append(Paragraph('Magnetise Media', ParagraphStyle('Brand', fontSize=13, textColor=MUTED, spaceAfter=20)))
    story.append(HRFlowable(width="100%", thickness=1, color=DARK, spaceAfter=20))

    budget = float(d['budget_total'] or 0)
    ops_fee = round(budget * 0.30, 2)
    view_guarantee = round(budget * 0.70, 2)

    # Invoice meta
    invoice_no = f"INV-{d['campaign_id']}"
    story.append(Table([
        ['Invoice No:', invoice_no, 'Issue Date:', str(d['start_date'])],
        ['Client:', d['full_name'], 'Due Date:', str(d['start_date'])],
        ['Email:', d['email'], 'Status:', 'PAID'],
    ], colWidths=[35*mm, 75*mm, 30*mm, 30*mm]))
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e0e0e0'), spaceAfter=16))

    # Line items
    story.append(Paragraph('Services', ParagraphStyle('H2', fontSize=13, fontName='Helvetica-Bold', spaceAfter=10)))
    items = [
        ['Description', 'Details', 'Amount'],
        ['Campaign Management (Ops Fee 30%)', f"{d['campaign_name']}", f"${ops_fee:,.2f}"],
        [f'View Guarantee (70%) — {d["target_views"]:,} views', f'{str(d["start_date"])} → {str(d["expected_end_date"])}', f"${view_guarantee:,.2f}"],
        ['', '', ''],
        ['TOTAL', '', f"${budget:,.2f}"],
    ]
    t = Table(items, colWidths=[90*mm, 60*mm, 30*mm])
    t.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('BACKGROUND', (0,0), (-1,0), DARK),
        ('ROWBACKGROUNDS', (0,1), (-1,-2), [colors.HexColor('#f9f9f9'), colors.white]),
        ('FONTNAME', (0,-1), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,-1), (-1,-1), 12),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('GRID', (0,0), (-1,-2), 0.3, colors.HexColor('#e0e0e0')),
        ('LINEABOVE', (0,-1), (-1,-1), 1.5, DARK),
    ]))
    story.append(t)
    story.append(Spacer(1, 30))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e0e0e0'), spaceAfter=8))
    story.append(Paragraph(
        f"Magnetise Media · magnetise.media · magnetisemedia.co@gmail.com",
        ParagraphStyle('Footer', fontSize=9, textColor=MUTED, alignment=1)
    ))

    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                     download_name=f"Invoice_{campaign_id}.pdf",
                     mimetype='application/pdf')

# ==========================================
# AUTH HELPERS
# ==========================================

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
# FORGOT PASSWORD — Also moved to DB
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

    if not user:
        cur.close()
        return jsonify({'success': False, 'message': 'No active account found.'})

    otp = str(random.randint(100000, 999999))
    expires_at = datetime.now() + timedelta(minutes=10)

    cur.execute("""
        INSERT INTO reset_otp_store (email, otp_code, expires_at, attempts)
        VALUES (%s, %s, %s, 0)
        ON DUPLICATE KEY UPDATE
            otp_code=VALUES(otp_code),
            expires_at=VALUES(expires_at),
            attempts=0,
            created_at=NOW()
    """, (email, otp, expires_at))
    mysql.connection.commit()
    cur.close()

    html_content = f"""
    <div style="font-family:Arial;padding:40px;background:#f4f4f4;">
        <div style="max-width:500px;margin:auto;background:white;padding:40px;border-radius:10px;">
            <h2 style="color:black;">Password Reset</h2>
            <p>Your password reset code:</p>
            <div style="font-size:34px;font-weight:800;letter-spacing:10px;background:black;color:white;padding:20px;border-radius:8px;text-align:center;">{otp}</div>
            <p style="margin-top:20px;color:#666;">Expires in 10 minutes.</p>
        </div>
    </div>
    """

    try:
        send_brevo_email(email, user['full_name'], "Reset Your Password — Magnetise Media", html_content)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/auth/reset-password', methods=['POST'])
@limiter.limit("5 per minute")
def reset_password():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    otp = data.get('otp', '').strip()
    new_password = data.get('new_password', '').strip()

    if len(new_password) < 8:
        return jsonify({'success': False, 'message': 'Password too short (min 8 characters)'})

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM reset_otp_store WHERE email=%s", (email,))
    record = cur.fetchone()

    if not record:
        cur.close()
        return jsonify({'success': False, 'message': 'No reset request found. Please request again.'})

    if record['attempts'] >= 5:
        cur.execute("DELETE FROM reset_otp_store WHERE email=%s", (email,))
        mysql.connection.commit()
        cur.close()
        return jsonify({'success': False, 'message': 'Too many attempts. Please request a new code.'})

    if datetime.now() > record['expires_at']:
        cur.execute("DELETE FROM reset_otp_store WHERE email=%s", (email,))
        mysql.connection.commit()
        cur.close()
        return jsonify({'success': False, 'message': 'Code expired. Please request a new one.'})

    if record['otp_code'] != otp:
        cur.execute("UPDATE reset_otp_store SET attempts=attempts+1 WHERE email=%s", (email,))
        mysql.connection.commit()
        cur.close()
        return jsonify({'success': False, 'message': 'Invalid code.'})

    password_hash = pbkdf2_sha256.hash(new_password)
    cur.execute("UPDATE users SET password_hash=%s WHERE email=%s", (password_hash, email))
    cur.execute("DELETE FROM reset_otp_store WHERE email=%s", (email,))
    mysql.connection.commit()
    cur.close()

    return jsonify({'success': True})


# ==========================================
# SECURITY HEADERS
# ==========================================

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
    print("Magnetise Media — Starting on http://localhost:5000")
    app.run(debug=False)