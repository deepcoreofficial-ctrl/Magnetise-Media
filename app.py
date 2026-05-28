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
app.config['MAX_CONTENT_LENGTH'] = 12 * 1024 * 1024   # room for uploaded report PDFs
app.secret_key = os.getenv("SECRET_KEY")

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().strip("'\"")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "").strip().strip("'\"")

# Public base URL used in client emails (login/dashboard buttons). Defaults to the
# live Render URL since the magnetise.media custom domain isn't pointed yet. Once
# you set up the custom domain in Render + DNS, set PUBLIC_URL=https://magnetise.media
PUBLIC_URL = os.getenv("PUBLIC_URL", "https://magnetise-media.onrender.com").rstrip("/")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# The Discord bot hits /api/bot/* on a schedule — it polls /api/bot/outbox every 60s
# (= 60 req/hour, already over the 50/hour default cap) and pushes stats hourly. Those
# calls are authenticated by X-Bot-Secret, so they're trusted. Exempt the whole bot API
# from rate limiting; otherwise the bot's own polling trips the per-IP limit and the site
# starts returning 429 (HTML) for campaign-created / outbox / refresh-stats. Human-facing
# routes (login, signup, etc.) keep their limits since they have different client IPs.
@limiter.request_filter
def _exempt_bot_endpoints():
    return request.path.startswith('/api/bot/')

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

            # Admin accounts. The super admin is env-based (code-fixed); rows here are
            # campaign managers. A row for the super email may also exist to hold a
            # changed password / profile picture.
            cur.execute("""
                CREATE TABLE IF NOT EXISTS admins (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255),
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255),
                    role VARCHAR(20) DEFAULT 'manager',
                    profile_pic MEDIUMTEXT,
                    created_at DATETIME DEFAULT NOW()
                )
            """)

            # Discord campaigns pushed by the bot. 'pending' until the super admin
            # syncs it to a website campaign, then 'approved' with the mapping.
            cur.execute("""
                CREATE TABLE IF NOT EXISTS discord_campaigns (
                    slug VARCHAR(255) PRIMARY KEY,
                    display_name VARCHAR(255),
                    created_at DATETIME,
                    sync_status VARCHAR(20) DEFAULT 'pending',
                    website_campaign_id VARCHAR(40),
                    synced_at DATETIME,
                    received_at DATETIME DEFAULT NOW()
                )
            """)

            # Client clip appeals (dispute a clip's current status)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS appeals (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    campaign_id VARCHAR(40),
                    clip_url VARCHAR(500),
                    clipper_name VARCHAR(255),
                    platform VARCHAR(50),
                    current_status VARCHAR(20),
                    desired_status VARCHAR(20),
                    reason TEXT,
                    client_email VARCHAR(255),
                    status VARCHAR(20) DEFAULT 'open',
                    decision VARCHAR(20),
                    resolved_by VARCHAR(255),
                    resolved_at DATETIME,
                    created_at DATETIME DEFAULT NOW(),
                    expires_at DATETIME,
                    INDEX idx_campaign (campaign_id)
                )
            """)

            # Manager requests for heavy actions (need super-admin approval)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS permits (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    campaign_id VARCHAR(40),
                    manager_email VARCHAR(255),
                    action VARCHAR(50),
                    note TEXT,
                    status VARCHAR(20) DEFAULT 'pending',
                    resolved_by VARCHAR(255),
                    resolved_at DATETIME,
                    created_at DATETIME DEFAULT NOW()
                )
            """)

            # Website->bot clip status changes (bot polls this to update Discord)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS clip_sync_outbox (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    campaign_id VARCHAR(40),
                    clip_url VARCHAR(500),
                    status VARCHAR(20),
                    reason TEXT,
                    processed INT DEFAULT 0,
                    created_at DATETIME DEFAULT NOW()
                )
            """)

            # Campaign reports (auto-generated or uploaded PDF)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    campaign_id VARCHAR(40) PRIMARY KEY,
                    mode VARCHAR(20),
                    pdf_data LONGTEXT,
                    created_at DATETIME DEFAULT NOW()
                )
            """)

            # Widen view columns INT -> BIGINT so large counts don't overflow (error 1264).
            # campaigns/users pre-exist so these are ALTERs; each is guarded so one failure
            # (e.g. table missing on a fresh DB) won't abort the rest.
            for _alter in (
                # Views: INT -> BIGINT so large counts don't overflow (error 1264)
                "ALTER TABLE campaigns MODIFY current_views BIGINT",
                "ALTER TABLE campaigns MODIFY target_views BIGINT",
                "ALTER TABLE views_history MODIFY views BIGINT NOT NULL",
                "ALTER TABLE top_clips MODIFY views BIGINT DEFAULT 0",
                "ALTER TABLE clips MODIFY views BIGINT DEFAULT 0",
                # Status columns: the live DB used different ENUM values than the code
                # ('ACTIVE_CAMPAIGN' vs 'ACTIVE'), causing "Data truncated" (error 1265).
                # Convert to plain text so every value the code uses is accepted.
                "ALTER TABLE users MODIFY account_status VARCHAR(20) DEFAULT 'PENDING'",
                "ALTER TABLE campaigns MODIFY status VARCHAR(20) DEFAULT 'ACTIVE'",
                # Password hashes are ~80-120 chars; make sure they're never truncated
                # (a truncated hash = client can never log in).
                "ALTER TABLE users MODIFY password_hash VARCHAR(255)",
                "ALTER TABLE users MODIFY rejection_reason TEXT",
                # Profile picture stored as a base64 data URL (survives Render redeploys)
                "ALTER TABLE users ADD COLUMN profile_pic MEDIUMTEXT",
                # Clip moderation status (pending/approved/rejected) — set by the Discord bot
                "ALTER TABLE top_clips ADD COLUMN status VARCHAR(20) DEFAULT 'pending'",
                "ALTER TABLE top_clips ADD COLUMN reject_reason TEXT",
                "ALTER TABLE clips ADD COLUMN status VARCHAR(20) DEFAULT 'pending'",
                "ALTER TABLE clips ADD COLUMN reject_reason TEXT",
                # Which admin/manager a campaign is assigned to (NULL = super admin)
                "ALTER TABLE campaigns ADD COLUMN assigned_admin_email VARCHAR(255)",
                # Who reviewed each clip (Discord admin name), shown to the client
                "ALTER TABLE top_clips ADD COLUMN reviewed_by VARCHAR(255)",
                "ALTER TABLE clips ADD COLUMN reviewed_by VARCHAR(255)",
                # Engagement metrics refreshed hourly by the bot
                "ALTER TABLE top_clips ADD COLUMN likes BIGINT DEFAULT 0",
                "ALTER TABLE top_clips ADD COLUMN comments BIGINT DEFAULT 0",
                "ALTER TABLE top_clips ADD COLUMN shares BIGINT DEFAULT 0",
                # last_updated is in the CREATE but a pre-existing top_clips can lack it
                # (CREATE IF NOT EXISTS won't add it) -> the /api/bot/refresh-stats UPDATE
                # used last_updated=NOW() and 500'd. Add it defensively.
                "ALTER TABLE top_clips ADD COLUMN last_updated DATETIME DEFAULT NOW()",
                "ALTER TABLE clips ADD COLUMN likes BIGINT DEFAULT 0",
                "ALTER TABLE clips ADD COLUMN comments BIGINT DEFAULT 0",
                "ALTER TABLE clips ADD COLUMN shares BIGINT DEFAULT 0",
                # youtube_video_id is in the CREATE but pre-existing clip tables lack it
                # (CREATE IF NOT EXISTS won't add it) -> the /api/bot/submit-clip INSERT
                # references it and 500'd with 1054 "Unknown column". Add it where missing.
                "ALTER TABLE top_clips ADD COLUMN youtube_video_id VARCHAR(50)",
                "ALTER TABLE clips ADD COLUMN youtube_video_id VARCHAR(50)",
                # Ensure the admins table has every expected column even if it pre-existed
                # (CREATE IF NOT EXISTS won't alter an existing table)
                "ALTER TABLE admins ADD COLUMN name VARCHAR(255)",
                "ALTER TABLE admins ADD COLUMN password_hash VARCHAR(255)",
                "ALTER TABLE admins ADD COLUMN role VARCHAR(20) DEFAULT 'manager'",
                "ALTER TABLE admins ADD COLUMN profile_pic MEDIUMTEXT",
                "ALTER TABLE admins ADD COLUMN created_at DATETIME DEFAULT NOW()",
                # password_hash may be NULL (super admin uses env password; the row just
                # holds name/picture). Pre-existing tables had it NOT NULL with no default.
                "ALTER TABLE admins MODIFY password_hash VARCHAR(255) NULL",
                # Normalize any legacy status value left over from the old schema
                "UPDATE users SET account_status='ACTIVE' WHERE account_status='ACTIVE_CAMPAIGN'",
            ):
                try:
                    cur.execute(_alter)
                except Exception as _ae:
                    print(f"skip alter: {_ae}")

            # Seed the super-admin row so the 'me' endpoints always UPDATE (never INSERT).
            if ADMIN_EMAIL:
                try:
                    cur.execute("SELECT id FROM admins WHERE email=%s", (ADMIN_EMAIL,))
                    if not cur.fetchone():
                        cur.execute(
                            "INSERT INTO admins (name, email, role, password_hash) VALUES (%s,%s,'super',%s)",
                            ('Admin', ADMIN_EMAIL, pbkdf2_sha256.hash(ADMIN_PASSWORD or 'changeme123'))
                        )
                except Exception as _se:
                    print(f"super seed skip: {_se}")

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
            <a href="{PUBLIC_URL}/dashboard" style="display:inline-block;background:#0a0a0a;color:#fff;font-weight:700;font-size:14px;padding:13px 36px;border-radius:6px;text-decoration:none;">View Dashboard →</a>
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

def resync_campaign_views(cur, campaign_id):
    """Recompute a campaign's current_views from APPROVED clips only.
    Logs a views_history point + runs the milestone check only when the total changes.
    Returns the new approved total."""
    cur.execute("SELECT COALESCE(SUM(views),0) AS total FROM top_clips WHERE campaign_id=%s AND status='approved'", (campaign_id,))
    total = int((cur.fetchone() or {}).get('total') or 0)
    cur.execute("SELECT current_views, target_views FROM campaigns WHERE campaign_id=%s", (campaign_id,))
    row = cur.fetchone()
    if not row:
        return total
    if total != int(row.get('current_views') or 0):
        cur.execute("UPDATE campaigns SET current_views=%s WHERE campaign_id=%s", (total, campaign_id))
        cur.execute("INSERT INTO views_history (campaign_id, views) VALUES (%s,%s)", (campaign_id, total))
        if row.get('target_views'):
            check_and_send_milestone_email(campaign_id, total, int(row['target_views']), cur)
    return total

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

def eff_admin():
    """Effective admin identity. Honors the super admin's 'view as manager' mode."""
    if session.get('acting_as_email'):
        return {'email': session['acting_as_email'], 'role': 'manager',
                'name': session.get('acting_as_name'), 'viewing_as': True,
                'real_email': session.get('admin_email')}
    return {'email': session.get('admin_email'), 'role': session.get('admin_role', 'super'),
            'name': session.get('admin_name'), 'viewing_as': False}

def is_super():
    """True only for the real super admin (not while viewing-as a manager)."""
    return bool(session.get('admin_logged_in')) and eff_admin()['role'] == 'super'

def can_access_campaign(cur, campaign_id):
    """Super can touch any campaign; a manager only campaigns assigned to them."""
    a = eff_admin()
    if a['role'] == 'super':
        return True
    cur.execute("SELECT assigned_admin_email FROM campaigns WHERE campaign_id=%s", (campaign_id,))
    row = cur.fetchone()
    return bool(row and row.get('assigned_admin_email') == a['email'])

@app.route('/api/admin/login', methods=['POST'])
@limiter.limit("5 per minute")
def admin_login():
    data = request.get_json()
    email = data.get('email', '').strip()
    password = data.get('password', '').strip()
    email_l = email.lower()

    cur = mysql.connection.cursor()

    # Super admin — code-fixed email. Env password always works (recovery); a changed
    # password saved in the admins row also works.
    if email_l == ADMIN_EMAIL.lower() and ADMIN_EMAIL:
        srow = None
        try:
            cur.execute("SELECT name, password_hash FROM admins WHERE email=%s", (ADMIN_EMAIL,))
            srow = cur.fetchone()
        except Exception:
            srow = None   # admins table not migrated yet — env password still works
        cur.close()
        ok = (password == ADMIN_PASSWORD)
        if not ok and srow and srow.get('password_hash'):
            try: ok = pbkdf2_sha256.verify(password, srow['password_hash'])
            except Exception: ok = False
        if ok:
            session.permanent = True
            session['admin_logged_in'] = True
            session['admin_email'] = ADMIN_EMAIL
            session['admin_role'] = 'super'
            session['admin_name'] = (srow.get('name') if srow else None) or 'Admin'
            session.pop('acting_as_email', None); session.pop('acting_as_name', None)
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Invalid credentials'})

    # Campaign manager — DB account
    row = None
    try:
        cur.execute("SELECT name, password_hash, role FROM admins WHERE email=%s", (email_l,))
        row = cur.fetchone()
    except Exception:
        row = None
    cur.close()
    if row and row.get('password_hash') and row.get('role') != 'super':
        try: ok = pbkdf2_sha256.verify(password, row['password_hash'])
        except Exception: ok = False
        if ok:
            session.permanent = True
            session['admin_logged_in'] = True
            session['admin_email'] = email_l
            session['admin_role'] = 'manager'
            session['admin_name'] = row.get('name') or email_l.split('@')[0]
            session.pop('acting_as_email', None); session.pop('acting_as_name', None)
            return jsonify({'success': True})

    return jsonify({'success': False, 'message': 'Invalid credentials'})

@app.route('/api/admin/check')
def admin_check():
    if session.get('admin_logged_in'):
        a = eff_admin()
        # profile pic for the effective admin (super or manager)
        pic = None
        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT profile_pic FROM admins WHERE email=%s", (a['email'],))
            r = cur.fetchone()
            cur.close()
            pic = r.get('profile_pic') if r else None
        except Exception:
            pic = None
        return jsonify({'authenticated': True, 'email': a['email'], 'role': a['role'],
                        'name': a['name'], 'viewing_as': a['viewing_as'], 'profile_pic': pic})
    return jsonify({'authenticated': False}), 401

@app.route('/api/admin/logout', methods=['POST'])
def admin_logout():
    for k in ('admin_logged_in', 'admin_email', 'admin_role', 'admin_name',
              'acting_as_email', 'acting_as_name'):
        session.pop(k, None)
    return jsonify({'success': True})

@app.route('/api/admin/pending')
def pending():
    if not is_super():
        return jsonify({'error': 'Unauthorized'}), 403
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
    a = eff_admin()
    cur = mysql.connection.cursor()
    if a['role'] != 'super':
        # Manager: only their assigned campaigns
        cur.execute("SELECT COUNT(*) cnt FROM campaigns WHERE status='ACTIVE' AND assigned_admin_email=%s", (a['email'],))
        active = cur.fetchone()['cnt']
        cur.execute("SELECT COUNT(*) cnt FROM campaigns WHERE status='COMPLETED' AND assigned_admin_email=%s", (a['email'],))
        completed = cur.fetchone()['cnt']
        cur.execute("SELECT COUNT(*) cnt FROM campaigns WHERE assigned_admin_email=%s", (a['email'],))
        total = cur.fetchone()['cnt']
        cur.close()
        return jsonify({'success': True, 'pending': 0, 'active': active, 'total': total, 'completed': completed})
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
    a = eff_admin()
    cur = mysql.connection.cursor()
    base = """
        SELECT u.user_id, u.full_name, u.email, u.account_status, u.rejection_reason,
               c.campaign_id, c.campaign_name, c.current_views, c.target_views,
               c.budget_total, c.cpm_rate, c.status AS campaign_status,
               c.start_date, c.expected_end_date, c.login_email_sent_at, c.assigned_admin_email
        FROM users u
        LEFT JOIN campaigns c ON u.campaign_id = c.campaign_id
    """
    if a['role'] == 'super':
        cur.execute(base + " ORDER BY u.created_at DESC")
    else:
        cur.execute(base + " WHERE c.assigned_admin_email=%s ORDER BY u.created_at DESC", (a['email'],))
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
    if not is_super():
        return jsonify({'success': False}), 403
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
    if not is_super():
        return jsonify({'success': False}), 403
    data = request.get_json()
    client_email = data.get('client_email')
    campaign_name = data.get('campaign_name')
    budget = data.get('budget_total')
    views = data.get('target_views')
    start = data.get('start_date')
    end = data.get('expected_end_date')
    password = data.get('password')

    if not all([client_email, campaign_name, budget, views, start, password]):
        return jsonify({'success': False, 'message': 'All fields required'}), 400
    end = end or None   # end date optional; shows "---" until the campaign ends

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

@app.route('/api/admin/create-account', methods=['POST'])
def admin_create_account():
    """Activate a signup as a client WITHOUT a campaign. They can log in and will
    see a 'no active campaign' state until a campaign is created for them."""
    if not is_super():
        return jsonify({'success': False}), 403
    data = request.get_json() or {}
    client_email = (data.get('client_email') or '').strip().lower()
    password = data.get('password') or ''
    if not client_email or not password:
        return jsonify({'success': False, 'message': 'Email and password required'}), 400
    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT user_id FROM users WHERE email=%s", (client_email,))
        if not cur.fetchone():
            cur.close()
            return jsonify({'success': False, 'message': 'Signup not found'}), 404
        # Activate the account with a password; leave campaign_id NULL (no campaign yet)
        cur.execute("UPDATE users SET account_status='ACTIVE', password_hash=%s WHERE email=%s",
                    (pbkdf2_sha256.hash(password), client_email))
        mysql.connection.commit()
        cur.close()
        return jsonify({'success': True, 'email': client_email})
    except Exception as e:
        try: mysql.connection.rollback()
        except Exception: pass
        try: cur.close()
        except Exception: pass
        return jsonify({'success': False, 'message': str(e)}), 400

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
    if not can_access_campaign(cur, campaign_id):
        cur.close()
        return jsonify({'success': False, 'message': 'Not allowed for this campaign'}), 403
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
    if new_status == 'COMPLETED' and eff_admin()['role'] != 'super':
        cur.close()
        return jsonify({'success': False, 'message': 'Ending a campaign needs a super-admin permit'}), 403
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
    if not is_super():
        return jsonify({'success': False}), 403

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
            <a href="{PUBLIC_URL}/client-login" style="display:inline-block;background:#0a0a0a;color:#ffffff;font-weight:700;font-size:15px;padding:14px 44px;border-radius:6px;text-decoration:none;">Login to Dashboard →</a>
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
    if not is_super():
        return jsonify({'success': False}), 403
    data = request.get_json()
    campaign_id = data.get('campaign_id')
    cur = mysql.connection.cursor()
    cur.execute("UPDATE campaigns SET status='COMPLETED', expected_end_date=CURDATE() WHERE campaign_id=%s", (campaign_id,))
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
    if not can_access_campaign(cur, campaign_id):
        cur.close(); return jsonify({'success': False, 'message': 'Not allowed'}), 403
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
    if not can_access_campaign(cur, campaign_id):
        cur.close(); return jsonify({'success': False, 'message': 'Not allowed'}), 403
    # Admin-added clips are approved immediately (admin is trusted)
    cur.execute("""
        INSERT INTO top_clips (campaign_id, clipper_name, platform, views, url, youtube_video_id, status)
        VALUES (%s,%s,%s,%s,%s,%s,'approved')
    """, (campaign_id, clipper_name, platform, views, url, yt_video_id))
    cur.execute("""
        INSERT INTO clips (campaign_id, clipper_name, platform, views, url, youtube_video_id, status)
        VALUES (%s,%s,%s,%s,%s,%s,'approved')
    """, (campaign_id, clipper_name, platform, views, url, yt_video_id))
    resync_campaign_views(cur, campaign_id)
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
    cur.execute("SELECT campaign_id FROM top_clips WHERE id=%s", (clip_id,))
    crow = cur.fetchone()
    cur.execute("DELETE FROM top_clips WHERE id=%s", (clip_id,))
    cur.execute("DELETE FROM clips WHERE id=%s", (clip_id,))
    if crow and crow.get('campaign_id'):
        resync_campaign_views(cur, crow['campaign_id'])
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

    # Keep the campaign total in sync (approved clips only)
    resync_campaign_views(cur, row['campaign_id'])
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

@app.route('/api/admin/reactivate-client', methods=['POST'])
def reactivate_client():
    if not is_super():
        return jsonify({'success': False}), 403
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
    if not is_super():
        return jsonify({'success': False}), 403
    data = request.get_json()
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'user_id required'}), 400
    cur = None
    try:
        cur = mysql.connection.cursor()
        # Resolve the client's email + EVERY campaign they own (a client can have more
        # than one, and users.campaign_id only points at the active one). We delete by
        # both campaign_id and client_email so no orphan row blocks the final delete.
        cur.execute("SELECT email, campaign_id FROM users WHERE user_id=%s", (user_id,))
        urow = cur.fetchone()
        if not urow:
            cur.close()
            return jsonify({'success': False, 'message': 'Client not found'}), 404
        email = urow.get('email')
        campaign_ids = set()
        if urow.get('campaign_id'):
            campaign_ids.add(urow['campaign_id'])
        if email:
            try:
                cur.execute("SELECT campaign_id FROM campaigns WHERE client_email=%s", (email,))
                for r in cur.fetchall():
                    if r.get('campaign_id'):
                        campaign_ids.add(r['campaign_id'])
            except Exception:
                pass
        # Safety net: drop FK enforcement for this delete so a stray constraint in the
        # pre-existing schema can't abort it (error 1451).
        try: cur.execute("SET FOREIGN_KEY_CHECKS=0")
        except Exception: pass
        # Remove every child row tied to those campaigns (each guarded so a missing
        # table/column is skipped instead of aborting the whole delete).
        for cid in campaign_ids:
            for tbl in ("views_history", "top_clips", "clips", "appeals", "permits",
                        "clip_sync_outbox", "reports", "milestone_emails_sent"):
                try: cur.execute(f"DELETE FROM {tbl} WHERE campaign_id=%s", (cid,))
                except Exception: pass
            try: cur.execute("DELETE FROM campaigns WHERE campaign_id=%s", (cid,))
            except Exception: pass
        # Rows keyed by the client's email
        if email:
            for tbl in ("otp_store", "reset_otp_store", "password_reset_requests", "appeals"):
                try: cur.execute(f"DELETE FROM {tbl} WHERE email=%s", (email,))
                except Exception: pass
            try: cur.execute("DELETE FROM appeals WHERE client_email=%s", (email,))
            except Exception: pass
            try: cur.execute("DELETE FROM campaigns WHERE client_email=%s", (email,))
            except Exception: pass
        # Finally the client
        cur.execute("DELETE FROM users WHERE user_id=%s", (user_id,))
        try: cur.execute("SET FOREIGN_KEY_CHECKS=1")
        except Exception: pass
        mysql.connection.commit()
        cur.close()
        return jsonify({'success': True})
    except Exception as e:
        try: mysql.connection.rollback()
        except Exception: pass
        try:
            if cur: cur.execute("SET FOREIGN_KEY_CHECKS=1"); cur.close()
        except Exception: pass
        return jsonify({'success': False, 'message': str(e)}), 400

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
# ROLES / ADMIN MANAGEMENT (super admin only)
# ==========================================

@app.route('/api/admin/campaigns')
def admin_campaigns_list():
    if not is_super():
        return jsonify({'success': False}), 403
    cur = mysql.connection.cursor()
    cur.execute("""SELECT campaign_id, campaign_name, status, assigned_admin_email
                   FROM campaigns ORDER BY created_at DESC""")
    rows = cur.fetchall()
    cur.close()
    return jsonify({'success': True, 'campaigns': rows})

@app.route('/api/admin/admins')
def admin_list_admins():
    if not is_super():
        return jsonify({'success': False}), 403
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, name, email, role, profile_pic, created_at FROM admins WHERE role!='super' ORDER BY created_at DESC")
    admins = cur.fetchall()
    cur.execute("SELECT assigned_admin_email, COUNT(*) c FROM campaigns WHERE assigned_admin_email IS NOT NULL GROUP BY assigned_admin_email")
    counts = {r['assigned_admin_email']: r['c'] for r in cur.fetchall()}
    cur.close()
    for a in admins:
        a['created_at'] = str(a['created_at'])
        a['campaigns'] = counts.get(a['email'], 0)
    return jsonify({'success': True, 'admins': admins})

@app.route('/api/admin/admins/create', methods=['POST'])
def admin_create_admin():
    if not is_super():
        return jsonify({'success': False}), 403
    data = request.get_json()
    name = (data.get('name') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password required'}), 400
    if len(password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400
    if email == ADMIN_EMAIL.lower():
        return jsonify({'success': False, 'message': 'That email is the super admin'}), 400
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM admins WHERE email=%s", (email,))
    if cur.fetchone():
        cur.close()
        return jsonify({'success': False, 'message': 'An admin with this email already exists'}), 400
    cur.execute("INSERT INTO admins (name, email, password_hash, role) VALUES (%s,%s,%s,'manager')",
                (name or email.split('@')[0], email, pbkdf2_sha256.hash(password)))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

@app.route('/api/admin/admins/delete', methods=['POST'])
def admin_delete_admin():
    if not is_super():
        return jsonify({'success': False}), 403
    admin_id = request.get_json().get('id')
    cur = mysql.connection.cursor()
    cur.execute("SELECT email, role FROM admins WHERE id=%s", (admin_id,))
    row = cur.fetchone()
    if not row or row['role'] == 'super':
        cur.close()
        return jsonify({'success': False, 'message': 'Cannot delete'}), 400
    cur.execute("UPDATE campaigns SET assigned_admin_email=NULL WHERE assigned_admin_email=%s", (row['email'],))
    cur.execute("DELETE FROM admins WHERE id=%s", (admin_id,))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

@app.route('/api/admin/admins/set-password', methods=['POST'])
def admin_set_admin_password():
    if not is_super():
        return jsonify({'success': False}), 403
    data = request.get_json()
    new_password = data.get('new_password') or ''
    if len(new_password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400
    cur = mysql.connection.cursor()
    cur.execute("UPDATE admins SET password_hash=%s WHERE id=%s AND role!='super'",
                (pbkdf2_sha256.hash(new_password), data.get('id')))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

@app.route('/api/admin/admins/profile/<int:admin_id>')
def admin_admin_profile(admin_id):
    if not is_super():
        return jsonify({'success': False}), 403
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, name, email, role, profile_pic, created_at FROM admins WHERE id=%s", (admin_id,))
    a = cur.fetchone()
    if not a:
        cur.close()
        return jsonify({'success': False, 'message': 'Not found'}), 404
    a['created_at'] = str(a['created_at'])
    cur.execute("SELECT campaign_id, campaign_name, status FROM campaigns WHERE assigned_admin_email=%s ORDER BY created_at DESC", (a['email'],))
    a['assigned_campaigns'] = cur.fetchall()
    cur.close()
    return jsonify({'success': True, 'admin': a})

@app.route('/api/admin/assign-campaign', methods=['POST'])
def admin_assign_campaign():
    if not is_super():
        return jsonify({'success': False}), 403
    data = request.get_json()
    campaign_id = data.get('campaign_id')
    admin_email = (data.get('admin_email') or '').strip().lower() or None   # None = super admin
    cur = mysql.connection.cursor()
    if admin_email:
        cur.execute("SELECT id FROM admins WHERE email=%s AND role!='super'", (admin_email,))
        if not cur.fetchone():
            cur.close()
            return jsonify({'success': False, 'message': 'Manager not found'}), 404
    cur.execute("UPDATE campaigns SET assigned_admin_email=%s WHERE campaign_id=%s", (admin_email, campaign_id))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

@app.route('/api/admin/impersonate-admin', methods=['POST'])
def admin_impersonate_admin():
    """Super admin 'view as' a manager."""
    if not is_super():
        return jsonify({'success': False}), 403
    data = request.get_json()
    cur = mysql.connection.cursor()
    if data.get('email'):
        cur.execute("SELECT name, email, role FROM admins WHERE email=%s", (data.get('email'),))
    else:
        cur.execute("SELECT name, email, role FROM admins WHERE id=%s", (data.get('id'),))
    row = cur.fetchone()
    cur.close()
    if not row or row['role'] == 'super':
        return jsonify({'success': False, 'message': 'Not found'}), 404
    session['acting_as_email'] = row['email']
    session['acting_as_name'] = row.get('name') or row['email']
    return jsonify({'success': True, 'redirect': '/admin/dashboard'})

@app.route('/admin/stop-impersonate-admin')
def admin_stop_impersonate_admin():
    if not session.get('admin_logged_in'):
        return redirect('/admin')
    session.pop('acting_as_email', None)
    session.pop('acting_as_name', None)
    return redirect('/admin/dashboard')

# ==========================================
# CAMPAIGNS-CLIPS SYNC (super admin only)
# ==========================================

@app.route('/api/admin/sync/list')
def admin_sync_list():
    if not is_super():
        return jsonify({'success': False}), 403
    try:
        cur = mysql.connection.cursor()
        # NOTE: do NOT JOIN discord_campaigns to campaigns in SQL. campaigns.campaign_id
        # (utf8mb4_general_ci) and discord_campaigns.website_campaign_id (utf8mb4_0900_ai_ci)
        # have different collations, so a SQL '=' between them throws MySQL 1267
        # "Illegal mix of collations" and the whole list comes back empty. We fetch each
        # table on its own and join them in Python, which is collation-proof.
        cur.execute("""
            SELECT slug, display_name, created_at, sync_status, website_campaign_id, synced_at
            FROM discord_campaigns
            ORDER BY received_at DESC
        """)
        rows = cur.fetchall()
        cur.execute("SELECT campaign_id, campaign_name, assigned_admin_email, status FROM campaigns")
        camps = cur.fetchall()
        camp_by_id = {str(c['campaign_id']): c for c in camps}
        for r in rows:
            r['created_at'] = str(r['created_at']) if r.get('created_at') else None
            r['synced_at'] = str(r['synced_at']) if r.get('synced_at') else None
            linked = camp_by_id.get(str(r['website_campaign_id'])) if r.get('website_campaign_id') else None
            r['website_campaign_name'] = linked['campaign_name'] if linked else None
            r['assigned_admin_email'] = linked['assigned_admin_email'] if linked else None
        linked_approved = {str(r['website_campaign_id']) for r in rows
                           if r.get('website_campaign_id') and r.get('sync_status') == 'approved'}
        available = [{'campaign_id': c['campaign_id'], 'campaign_name': c['campaign_name']}
                     for c in camps
                     if c.get('status') == 'ACTIVE' and str(c['campaign_id']) not in linked_approved]
        cur.execute("SELECT name, email FROM admins WHERE role!='super' ORDER BY email")
        managers = cur.fetchall()
        cur.close()
        return jsonify({
            'success': True,
            'pending':  [r for r in rows if r['sync_status'] == 'pending'],
            'approved': [r for r in rows if r['sync_status'] == 'approved'],
            'available_campaigns': available,
            'managers': managers,
        })
    except Exception as e:
        try: cur.close()
        except Exception: pass
        return jsonify({'success': True, 'pending': [], 'approved': [],
                        'available_campaigns': [], 'managers': [], 'note': str(e)})

@app.route('/api/admin/sync/approve', methods=['POST'])
def admin_sync_approve():
    if not is_super():
        return jsonify({'success': False}), 403
    data = request.get_json()
    slug = (data.get('slug') or '').strip()
    website_campaign_id = (data.get('website_campaign_id') or '').strip()
    assigned = (data.get('assigned_admin_email') or '').strip().lower() or None   # None = super admin
    if not slug or not website_campaign_id:
        return jsonify({'success': False, 'message': 'slug and website campaign required'}), 400
    cur = mysql.connection.cursor()
    cur.execute("SELECT campaign_id FROM campaigns WHERE campaign_id=%s", (website_campaign_id,))
    if not cur.fetchone():
        cur.close()
        return jsonify({'success': False, 'message': 'Website campaign not found'}), 404
    if assigned:
        cur.execute("SELECT id FROM admins WHERE email=%s AND role!='super'", (assigned,))
        if not cur.fetchone():
            cur.close()
            return jsonify({'success': False, 'message': 'Manager not found'}), 404
    cur.execute("UPDATE discord_campaigns SET sync_status='approved', website_campaign_id=%s, synced_at=NOW() WHERE slug=%s",
                (website_campaign_id, slug))
    cur.execute("UPDATE campaigns SET assigned_admin_email=%s WHERE campaign_id=%s", (assigned, website_campaign_id))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

@app.route('/api/admin/sync/unlink', methods=['POST'])
def admin_sync_unlink():
    if not is_super():
        return jsonify({'success': False}), 403
    slug = (request.get_json().get('slug') or '').strip()
    cur = mysql.connection.cursor()
    cur.execute("UPDATE discord_campaigns SET sync_status='pending', website_campaign_id=NULL, synced_at=NULL WHERE slug=%s", (slug,))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

# ==========================================
# APPEALS (client disputes) + PERMITS (manager requests) + REPORTS
# ==========================================

@app.route('/api/admin/appeals')
def admin_appeals_list():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    a = eff_admin()
    try:
        cur = mysql.connection.cursor()
        base = "SELECT ap.*, c.campaign_name FROM appeals ap LEFT JOIN campaigns c ON ap.campaign_id=c.campaign_id "
        if a['role'] == 'super':
            cur.execute(base + "ORDER BY ap.created_at DESC")
        else:
            cur.execute(base + "WHERE c.assigned_admin_email=%s ORDER BY ap.created_at DESC", (a['email'],))
        rows = cur.fetchall()
        cur.close()
    except Exception:
        return jsonify({'success': True, 'appeals': []})
    now = datetime.now()
    out = []
    for r in rows:
        exp = r.get('expires_at')
        st = r['status']
        if st == 'open' and exp and now > exp:
            st = 'expired'
        out.append({
            'id': r['id'], 'campaign_id': r['campaign_id'], 'campaign_name': r.get('campaign_name'),
            'clip_url': r['clip_url'], 'clipper_name': r['clipper_name'], 'platform': r['platform'],
            'current_status': r['current_status'], 'desired_status': r['desired_status'],
            'reason': r['reason'], 'status': st, 'decision': r.get('decision'),
            'resolved_by': r.get('resolved_by'),
            'created_at': str(r['created_at']) if r.get('created_at') else None,
            'expires_at': str(exp) if exp else None,
        })
    return jsonify({'success': True, 'appeals': out})

@app.route('/api/admin/appeals/resolve', methods=['POST'])
def admin_appeals_resolve():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    data = request.get_json()
    appeal_id = data.get('id')
    decision  = (data.get('decision') or '').strip().lower()   # approved / rejected (clip outcome)
    reason    = (data.get('reason') or '').strip()
    if decision not in ('approved', 'rejected'):
        return jsonify({'success': False, 'message': 'decision must be approved/rejected'}), 400
    cur = mysql.connection.cursor()
    cur.execute("SELECT campaign_id, clip_url FROM appeals WHERE id=%s AND status='open'", (appeal_id,))
    ap = cur.fetchone()
    if not ap:
        cur.close(); return jsonify({'success': False, 'message': 'Appeal not found or already resolved'}), 404
    if not can_access_campaign(cur, ap['campaign_id']):
        cur.close(); return jsonify({'success': False}), 403
    who = eff_admin().get('name') or eff_admin().get('email')
    cur.execute("UPDATE top_clips SET status=%s, reject_reason=%s, reviewed_by=%s WHERE campaign_id=%s AND url=%s",
                (decision, reason or None, who, ap['campaign_id'], ap['clip_url']))
    cur.execute("UPDATE clips SET status=%s, reject_reason=%s, reviewed_by=%s WHERE campaign_id=%s AND url=%s",
                (decision, reason or None, who, ap['campaign_id'], ap['clip_url']))
    resync_campaign_views(cur, ap['campaign_id'])
    cur.execute("INSERT INTO clip_sync_outbox (campaign_id, clip_url, status, reason) VALUES (%s,%s,%s,%s)",
                (ap['campaign_id'], ap['clip_url'], decision, reason or None))
    cur.execute("UPDATE appeals SET status='resolved', decision=%s, resolved_by=%s, resolved_at=NOW() WHERE id=%s",
                (decision, who, appeal_id))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

@app.route('/api/admin/appeals/extend', methods=['POST'])
def admin_appeals_extend():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    data = request.get_json()
    hours = int(data.get('hours') or 48)
    cur = mysql.connection.cursor()
    cur.execute("UPDATE appeals SET expires_at = DATE_ADD(COALESCE(expires_at, NOW()), INTERVAL %s HOUR) WHERE id=%s AND status='open'",
                (hours, data.get('id')))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

@app.route('/api/admin/permits/request', methods=['POST'])
def admin_permit_request():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    a = eff_admin()
    if a['role'] == 'super':
        return jsonify({'success': False, 'message': 'Super admin does not need a permit'}), 400
    data = request.get_json()
    campaign_id = data.get('campaign_id')
    action = (data.get('action') or '').strip()
    note = (data.get('note') or '').strip()
    if not campaign_id or not action:
        return jsonify({'success': False, 'message': 'campaign and action required'}), 400
    cur = mysql.connection.cursor()
    if not can_access_campaign(cur, campaign_id):
        cur.close(); return jsonify({'success': False}), 403
    cur.execute("INSERT INTO permits (campaign_id, manager_email, action, note) VALUES (%s,%s,%s,%s)",
                (campaign_id, a['email'], action, note))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

@app.route('/api/admin/permits')
def admin_permits_list():
    if not is_super():
        return jsonify({'success': False}), 403
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT p.*, c.campaign_name FROM permits p LEFT JOIN campaigns c ON p.campaign_id=c.campaign_id ORDER BY p.created_at DESC")
        rows = cur.fetchall()
        cur.close()
    except Exception:
        return jsonify({'success': True, 'permits': []})
    for r in rows:
        r['created_at'] = str(r['created_at']) if r.get('created_at') else None
        r['resolved_at'] = str(r['resolved_at']) if r.get('resolved_at') else None
    return jsonify({'success': True, 'permits': rows})

@app.route('/api/admin/permits/resolve', methods=['POST'])
def admin_permit_resolve():
    if not is_super():
        return jsonify({'success': False}), 403
    data = request.get_json()
    pid = data.get('id')
    approve = bool(data.get('approve'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT campaign_id, action, status FROM permits WHERE id=%s", (pid,))
    p = cur.fetchone()
    if not p or p['status'] != 'pending':
        cur.close(); return jsonify({'success': False, 'message': 'Not found or already resolved'}), 404
    who = session.get('admin_name') or session.get('admin_email')
    if approve:
        if p['action'] == 'complete_campaign':
            cur.execute("UPDATE campaigns SET status='COMPLETED', expected_end_date=CURDATE() WHERE campaign_id=%s", (p['campaign_id'],))
            cur.execute("UPDATE users SET account_status='COMPLETED' WHERE campaign_id=%s", (p['campaign_id'],))
        cur.execute("UPDATE permits SET status='approved', resolved_by=%s, resolved_at=NOW() WHERE id=%s", (who, pid))
    else:
        cur.execute("UPDATE permits SET status='denied', resolved_by=%s, resolved_at=NOW() WHERE id=%s", (who, pid))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

@app.route('/api/admin/report/set', methods=['POST'])
def admin_report_set():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    data = request.get_json()
    campaign_id = data.get('campaign_id')
    mode = (data.get('mode') or 'auto').strip().lower()
    pdf_data = data.get('pdf_data')
    cur = mysql.connection.cursor()
    if not can_access_campaign(cur, campaign_id):
        cur.close(); return jsonify({'success': False}), 403
    if mode == 'uploaded':
        if not pdf_data or not pdf_data.startswith('data:application/pdf'):
            cur.close(); return jsonify({'success': False, 'message': 'Upload a PDF file'}), 400
        if len(pdf_data) > 9_000_000:
            cur.close(); return jsonify({'success': False, 'message': 'PDF too large'}), 400
    else:
        pdf_data = None
    cur.execute("""INSERT INTO reports (campaign_id, mode, pdf_data) VALUES (%s,%s,%s)
                   ON DUPLICATE KEY UPDATE mode=VALUES(mode), pdf_data=VALUES(pdf_data), created_at=NOW()""",
                (campaign_id, mode, pdf_data))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

# ==========================================
# ADMIN ACCOUNT SETTINGS (own password + picture)
# ==========================================

@app.route('/api/admin/me/change-password', methods=['POST'])
def admin_change_own_password():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    new_password = request.get_json().get('new_password') or ''
    if len(new_password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400
    email = session.get('admin_email')                 # real logged-in admin
    role = session.get('admin_role', 'super')
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM admins WHERE email=%s", (email,))
        if cur.fetchone():
            cur.execute("UPDATE admins SET password_hash=%s WHERE email=%s", (pbkdf2_sha256.hash(new_password), email))
        else:
            cur.execute("INSERT INTO admins (name, email, password_hash, role) VALUES (%s,%s,%s,%s)",
                        (session.get('admin_name') or 'Admin', email, pbkdf2_sha256.hash(new_password), role))
        mysql.connection.commit()
        cur.close()
        return jsonify({'success': True})
    except Exception as e:
        try: cur.close()
        except Exception: pass
        return jsonify({'success': False, 'message': f'Could not save: {e}'}), 400

@app.route('/api/admin/me/profile-pic', methods=['POST'])
def admin_set_own_pic():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    image = (request.get_json().get('image') or '').strip()
    if image and not image.startswith('data:image/'):
        return jsonify({'success': False, 'message': 'Invalid image'}), 400
    if len(image) > 3_000_000:
        return jsonify({'success': False, 'message': 'Image too large'}), 400
    email = session.get('admin_email')
    role = session.get('admin_role', 'super')
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM admins WHERE email=%s", (email,))
        if cur.fetchone():
            cur.execute("UPDATE admins SET profile_pic=%s WHERE email=%s", (image or None, email))
        else:
            cur.execute("INSERT INTO admins (name, email, role, password_hash, profile_pic) VALUES (%s,%s,%s,%s,%s)",
                        (session.get('admin_name') or 'Admin', email, role,
                         pbkdf2_sha256.hash(ADMIN_PASSWORD or 'changeme123'), image or None))
        mysql.connection.commit()
        cur.close()
        return jsonify({'success': True})
    except Exception as e:
        try: cur.close()
        except Exception: pass
        return jsonify({'success': False, 'message': f'Could not save: {e}'}), 400

@app.route('/api/admin/me/set-name', methods=['POST'])
def admin_set_own_name():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    name = (request.get_json().get('name') or '').strip()
    if not name:
        return jsonify({'success': False, 'message': 'Name required'}), 400
    email = session.get('admin_email')
    role = session.get('admin_role', 'super')
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM admins WHERE email=%s", (email,))
        if cur.fetchone():
            cur.execute("UPDATE admins SET name=%s WHERE email=%s", (name, email))
        else:
            cur.execute("INSERT INTO admins (name, email, role, password_hash) VALUES (%s,%s,%s,%s)",
                        (name, email, role, pbkdf2_sha256.hash(ADMIN_PASSWORD or 'changeme123')))
        mysql.connection.commit()
        cur.close()
        session['admin_name'] = name
        return jsonify({'success': True})
    except Exception as e:
        try: cur.close()
        except Exception: pass
        return jsonify({'success': False, 'message': f'Could not save: {e}'}), 400

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
    campaign_slug= (data.get('campaign_slug') or '').strip()   # Discord campaign → resolved on the site
    clipper_name = data.get('clipper_name', '').strip()
    platform     = data.get('platform', '').strip()      # TikTok / YouTube / Reels / Shorts
    views        = int(data.get('views', 0))
    url          = data.get('url', '').strip()
    status       = (data.get('status') or 'pending').strip().lower()   # bot may submit pre-approved
    if status not in ('pending', 'approved', 'rejected'):
        status = 'pending'

    if not (campaign_id or campaign_slug) or not clipper_name or not platform:
        return jsonify({'success': False, 'message': 'campaign (id or slug), clipper_name, platform required'}), 400

    # Extract YouTube video ID from URL
    yt_video_id = None
    if 'youtube.com' in url or 'youtu.be' in url:
        match = re.search(r'(?:v=|youtu\.be/|shorts/)([A-Za-z0-9_-]{11})', url)
        if match:
            yt_video_id = match.group(1)

    cur = mysql.connection.cursor()
    try:
        # Route Discord submissions by slug -> mapped website campaign
        if campaign_slug:
            cur.execute("SELECT website_campaign_id FROM discord_campaigns WHERE slug=%s AND sync_status='approved'", (campaign_slug,))
            m = cur.fetchone()
            if not m or not m.get('website_campaign_id'):
                cur.close()
                return jsonify({'success': False, 'message': 'Campaign not synced to a website campaign yet'}), 409
            campaign_id = m['website_campaign_id']

        # Check campaign exists
        cur.execute("SELECT campaign_id FROM campaigns WHERE campaign_id=%s", (campaign_id,))
        if not cur.fetchone():
            cur.close()
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404

        # Insert clip into both tables with its moderation status
        cur.execute("""
            INSERT INTO top_clips (campaign_id, clipper_name, platform, views, url, youtube_video_id, status)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (campaign_id, clipper_name, platform, views, url, yt_video_id, status))
        cur.execute("""
            INSERT INTO clips (campaign_id, clipper_name, platform, views, url, youtube_video_id, status)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (campaign_id, clipper_name, platform, views, url, yt_video_id, status))

        # Only APPROVED clips count toward the campaign total / graph (pending submits don't move it)
        total_views = resync_campaign_views(cur, campaign_id)

        mysql.connection.commit()
        cur.close()
        return jsonify({'success': True, 'total_views': total_views})
    except Exception as e:
        try: mysql.connection.rollback()
        except Exception: pass
        try: cur.close()
        except Exception: pass
        app.logger.error("submit-clip failed: %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/bot/set-clip-status', methods=['POST'])
def bot_set_clip_status():
    """Discord bot calls this when an admin approves/rejects a clip.
    Only approved clips count toward views, so this re-syncs the campaign total."""
    if not bot_auth():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.get_json()
    campaign_id   = (data.get('campaign_id') or '').strip()
    campaign_slug = (data.get('campaign_slug') or '').strip()
    url           = (data.get('url') or '').strip()
    status        = (data.get('status') or '').strip().lower()
    reason        = data.get('reject_reason')
    reviewed_by   = data.get('reviewed_by')

    if status not in ('pending', 'approved', 'rejected'):
        return jsonify({'success': False, 'message': 'status must be pending/approved/rejected'}), 400
    if not url:
        return jsonify({'success': False, 'message': 'url required'}), 400

    cur = mysql.connection.cursor()
    if campaign_slug and not campaign_id:
        cur.execute("SELECT website_campaign_id FROM discord_campaigns WHERE slug=%s", (campaign_slug,))
        m = cur.fetchone()
        campaign_id = (m['website_campaign_id'] if m and m.get('website_campaign_id') else '')

    if campaign_id:
        cur.execute("UPDATE top_clips SET status=%s, reject_reason=%s, reviewed_by=%s WHERE campaign_id=%s AND url=%s",
                    (status, reason, reviewed_by, campaign_id, url))
        cur.execute("UPDATE clips SET status=%s, reject_reason=%s, reviewed_by=%s WHERE campaign_id=%s AND url=%s",
                    (status, reason, reviewed_by, campaign_id, url))
    else:
        cur.execute("UPDATE top_clips SET status=%s, reject_reason=%s, reviewed_by=%s WHERE url=%s", (status, reason, reviewed_by, url))
        cur.execute("UPDATE clips SET status=%s, reject_reason=%s, reviewed_by=%s WHERE url=%s", (status, reason, reviewed_by, url))

    # Re-sync every campaign this URL belongs to
    cur.execute("SELECT DISTINCT campaign_id FROM top_clips WHERE url=%s", (url,))
    cids = [r['campaign_id'] for r in cur.fetchall()]
    if campaign_id and campaign_id not in cids:
        cids.append(campaign_id)
    total = 0
    for cid in cids:
        total = resync_campaign_views(cur, cid)

    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True, 'total_views': total})


@app.route('/api/bot/remove-clip', methods=['POST'])
def bot_remove_clip():
    """Discord bot calls this when a clip is removed (by clipper or admin) or a
    clipper leaves a campaign. Deletes the matching clip(s) from the website and
    re-syncs the campaign total so removed approved views are subtracted.
    Body: campaign_slug (or campaign_id) + EITHER url (one clip) OR clipper_name
    (all of that clipper's clips — the leave case)."""
    if not bot_auth():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    data = request.get_json() or {}
    campaign_id   = (data.get('campaign_id') or '').strip()
    campaign_slug = (data.get('campaign_slug') or '').strip()
    url           = (data.get('url') or '').strip()
    clipper_name  = (data.get('clipper_name') or '').strip()
    if not url and not clipper_name:
        return jsonify({'success': False, 'message': 'url or clipper_name required'}), 400
    cur = mysql.connection.cursor()
    try:
        # Resolve the Discord slug to its linked website campaign.
        if campaign_slug:
            cur.execute("SELECT website_campaign_id FROM discord_campaigns WHERE slug=%s AND sync_status='approved'", (campaign_slug,))
            m = cur.fetchone()
            if not m or not m.get('website_campaign_id'):
                cur.close()
                # Not linked -> the clip was never on the website; nothing to remove.
                return jsonify({'success': True, 'removed': 0, 'note': 'campaign not synced'})
            campaign_id = m['website_campaign_id']
        if not campaign_id:
            cur.close()
            return jsonify({'success': False, 'message': 'campaign required'}), 400

        if url:
            cur.execute("DELETE FROM top_clips WHERE campaign_id=%s AND url=%s", (campaign_id, url))
            removed = cur.rowcount
            cur.execute("DELETE FROM clips WHERE campaign_id=%s AND url=%s", (campaign_id, url))
        else:
            # Leave case: remove every clip this clipper submitted to the campaign.
            cur.execute("DELETE FROM top_clips WHERE campaign_id=%s AND clipper_name=%s", (campaign_id, clipper_name))
            removed = cur.rowcount
            cur.execute("DELETE FROM clips WHERE campaign_id=%s AND clipper_name=%s", (campaign_id, clipper_name))

        # Recompute the campaign total from remaining approved clips.
        total = resync_campaign_views(cur, campaign_id)
        mysql.connection.commit()
        cur.close()
        return jsonify({'success': True, 'removed': removed, 'total_views': total})
    except Exception as e:
        try: mysql.connection.rollback()
        except Exception: pass
        try: cur.close()
        except Exception: pass
        app.logger.error("remove-clip failed: %s", e)
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/bot/campaign-created', methods=['POST'])
def bot_campaign_created():
    """Discord bot pushes a newly-created campaign. Lands in the Pending sync list."""
    if not bot_auth():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    data = request.get_json()
    slug = (data.get('slug') or data.get('campaign_slug') or '').strip()
    if not slug:
        return jsonify({'success': False, 'message': 'slug required'}), 400
    display = data.get('display_name') or slug
    created = data.get('created_at')   # optional 'YYYY-MM-DD HH:MM:SS'
    cur = mysql.connection.cursor()
    # New slug -> pending. Re-pushed slug (re-create / Re-sync button) -> force back
    # to pending UNLESS it's already approved (don't unlink a linked campaign).
    # This guarantees a freshly created/re-synced campaign always shows in the
    # Pending list, even if a stale 'closed' row for the same slug existed.
    cur.execute("""
        INSERT INTO discord_campaigns (slug, display_name, created_at, sync_status)
        VALUES (%s,%s,%s,'pending')
        ON DUPLICATE KEY UPDATE
            display_name=VALUES(display_name),
            sync_status=IF(sync_status='approved', sync_status, 'pending')
    """, (slug, display, created))
    mysql.connection.commit()
    # Read back the resulting status so the response/logs prove what happened.
    cur.execute("SELECT sync_status FROM discord_campaigns WHERE slug=%s", (slug,))
    row = cur.fetchone()
    status = (row.get('sync_status') if row else None)
    cur.close()
    app.logger.info("campaign-created received: slug=%s display=%s -> status=%s", slug, display, status)
    return jsonify({'success': True, 'slug': slug, 'sync_status': status})


@app.route('/api/bot/campaign-finished', methods=['POST'])
def bot_campaign_finished():
    """Discord bot pushes a campaign deletion. Closes the mapped website campaign."""
    if not bot_auth():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    slug = (request.get_json().get('slug') or request.get_json().get('campaign_slug') or '').strip()
    if not slug:
        return jsonify({'success': False, 'message': 'slug required'}), 400
    cur = mysql.connection.cursor()
    cur.execute("SELECT website_campaign_id FROM discord_campaigns WHERE slug=%s", (slug,))
    row = cur.fetchone()
    if row and row.get('website_campaign_id'):
        cid = row['website_campaign_id']
        cur.execute("UPDATE campaigns SET status='COMPLETED', expected_end_date=CURDATE() WHERE campaign_id=%s", (cid,))
        cur.execute("UPDATE users SET account_status='COMPLETED' WHERE campaign_id=%s", (cid,))
    cur.execute("UPDATE discord_campaigns SET sync_status='closed' WHERE slug=%s", (slug,))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})


@app.route('/api/bot/outbox', methods=['POST'])
def bot_outbox():
    """Bot polls this to apply website-side clip status changes (appeal resolutions) back to Discord."""
    if not bot_auth():
        return jsonify({'success': False}), 401
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT o.id, o.clip_url, o.status, o.reason, d.slug
        FROM clip_sync_outbox o
        LEFT JOIN discord_campaigns d ON o.campaign_id = d.website_campaign_id
        WHERE o.processed=0 ORDER BY o.id ASC LIMIT 50
    """)
    rows = cur.fetchall()
    ids = [r['id'] for r in rows]
    if ids:
        fmt = ','.join(['%s'] * len(ids))
        cur.execute(f"UPDATE clip_sync_outbox SET processed=1 WHERE id IN ({fmt})", tuple(ids))
        mysql.connection.commit()
    cur.close()
    return jsonify({'success': True, 'changes': rows})


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

    # Re-sync totals for every affected campaign (approved clips only)
    for cid in affected_campaigns:
        resync_campaign_views(cur, cid)

    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True, 'campaigns_updated': list(affected_campaigns)})

@app.route('/api/bot/refresh-stats', methods=['POST'])
def bot_refresh_stats():
    """Hourly stats refresh from the bot. Matches clips by URL (works for every
    platform) and updates views/likes/comments/shares, then re-syncs approved
    views into the campaign total + history graph."""
    if not bot_auth():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    updates = (request.get_json() or {}).get('updates', [])
    if not updates:
        return jsonify({'success': False, 'message': 'No updates'}), 400
    cur = None
    try:
        cur = mysql.connection.cursor()
        affected = set()
        for u in updates:
            url = (u.get('url') or '').strip()
            if not url:
                continue
            views    = int(u.get('views') or 0)
            likes    = int(u.get('likes') or 0)
            comments = int(u.get('comments') or 0)
            shares   = int(u.get('shares') or 0)
            cur.execute("""UPDATE top_clips SET views=%s, likes=%s, comments=%s, shares=%s, last_updated=NOW()
                           WHERE url=%s""", (views, likes, comments, shares, url))
            cur.execute("UPDATE clips SET views=%s, likes=%s, comments=%s, shares=%s WHERE url=%s",
                        (views, likes, comments, shares, url))
            cur.execute("SELECT DISTINCT campaign_id FROM top_clips WHERE url=%s", (url,))
            for r in cur.fetchall():
                if r.get('campaign_id'):
                    affected.add(r['campaign_id'])
        for cid in affected:
            resync_campaign_views(cur, cid)
        mysql.connection.commit()
        cur.close()
        return jsonify({'success': True, 'campaigns_updated': list(affected)})
    except Exception as e:
        try: mysql.connection.rollback()
        except Exception: pass
        try:
            if cur: cur.close()
        except Exception: pass
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin/set-cpm', methods=['POST'])
def admin_set_cpm():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False}), 401
    data = request.get_json()
    campaign_id = data.get('campaign_id')
    cpm_rate = data.get('cpm_rate')
    cur = mysql.connection.cursor()
    if not can_access_campaign(cur, campaign_id):
        cur.close(); return jsonify({'success': False, 'message': 'Not allowed'}), 403
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
        SELECT u.full_name, u.email, u.account_status, u.rejection_reason, u.profile_pic,
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
    report_avail = False
    if row and row.get('campaign_id'):
        cur.execute("SELECT campaign_id FROM reports WHERE campaign_id=%s", (row['campaign_id'],))
        report_avail = bool(cur.fetchone())
    cur.close()

    if not row:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    row['all_campaigns'] = all_campaigns
    row['report_available'] = report_avail

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

@app.route('/api/dashboard/profile-pic', methods=['POST'])
def update_profile_pic():
    """Store a base64 data-URL profile picture for the logged-in client. Empty value clears it."""
    if 'user_email' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    data = request.get_json()
    image = (data.get('image') or '').strip()
    if image and not image.startswith('data:image/'):
        return jsonify({'success': False, 'message': 'Invalid image format'}), 400
    if len(image) > 3_000_000:  # ~3MB of base64; the UI resizes well below this
        return jsonify({'success': False, 'message': 'Image too large — please choose a smaller one'}), 400
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET profile_pic=%s WHERE email=%s", (image or None, session['user_email']))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

@app.route('/api/dashboard/update-name', methods=['POST'])
def dashboard_update_name():
    """Client changes their own display name."""
    if 'user_email' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    name = (request.get_json().get('name') or '').strip()
    if not name:
        return jsonify({'success': False, 'message': 'Name required'}), 400
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET full_name=%s WHERE email=%s", (name[:255], session['user_email']))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

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
        FROM top_clips WHERE campaign_id=%s AND status='approved' AND views>=10000
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
        FROM top_clips WHERE campaign_id=%s AND status='approved'
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
        FROM top_clips WHERE campaign_id=%s AND status='approved'
        GROUP BY platform ORDER BY total_views DESC
    """, (user['campaign_id'],))
    rows = cur.fetchall()
    cur.close()
    return jsonify({'success': True, 'breakdown': rows})

@app.route('/api/dashboard/clips')
def dashboard_all_clips():
    """Every clip for the logged-in client's campaign (any status) + summary counts."""
    if 'user_email' not in session:
        return jsonify({'success': False}), 401
    cur = mysql.connection.cursor()
    cur.execute("SELECT campaign_id FROM users WHERE email=%s", (session['user_email'],))
    user = cur.fetchone()
    empty = {'total': 0, 'approved': 0, 'pending': 0, 'rejected': 0, 'approved_views': 0}
    if not user or not user['campaign_id']:
        cur.close()
        return jsonify({'success': True, 'clips': [], 'summary': empty})
    cid = user['campaign_id']
    cur.execute("""
        SELECT id, clipper_name, platform, views, url, status, added_at, reviewed_by, reject_reason,
               likes, comments, shares
        FROM top_clips WHERE campaign_id=%s ORDER BY added_at DESC
    """, (cid,))
    clips = cur.fetchall()
    for c in clips:
        c['added_at'] = str(c['added_at'])
    cur.execute("""
        SELECT COUNT(*) AS total,
               COALESCE(SUM(status='approved'),0) AS approved,
               COALESCE(SUM(status='pending'),0)  AS pending,
               COALESCE(SUM(status='rejected'),0) AS rejected,
               COALESCE(SUM(CASE WHEN status='approved' THEN views ELSE 0 END),0) AS approved_views
        FROM top_clips WHERE campaign_id=%s
    """, (cid,))
    s = cur.fetchone() or {}
    cur.execute("SELECT assigned_admin_email FROM campaigns WHERE campaign_id=%s", (cid,))
    crow = cur.fetchone()
    managed_by = 'Magnetise Media'
    if crow and crow.get('assigned_admin_email'):
        cur.execute("SELECT name FROM admins WHERE email=%s", (crow['assigned_admin_email'],))
        mrow = cur.fetchone()
        managed_by = (mrow.get('name') if mrow else None) or crow['assigned_admin_email']
    cur.close()
    summary = {
        'total': int(s.get('total') or 0),
        'approved': int(s.get('approved') or 0),
        'pending': int(s.get('pending') or 0),
        'rejected': int(s.get('rejected') or 0),
        'approved_views': int(s.get('approved_views') or 0),
        'managed_by': managed_by,
    }
    return jsonify({'success': True, 'clips': clips, 'summary': summary})

@app.route('/api/dashboard/appeal', methods=['POST'])
def dashboard_appeal():
    """Client disputes a clip's current status. Goes to the Appeals queue (48h)."""
    if 'user_email' not in session:
        return jsonify({'success': False}), 401
    data = request.get_json()
    clip_url = (data.get('clip_url') or '').strip()
    desired  = (data.get('desired_status') or '').strip().lower()
    reason   = (data.get('reason') or '').strip()
    if desired not in ('approved', 'rejected'):
        return jsonify({'success': False, 'message': 'Pick approve or reject'}), 400
    if not clip_url:
        return jsonify({'success': False, 'message': 'Clip required'}), 400
    email = session['user_email']
    cur = mysql.connection.cursor()
    cur.execute("SELECT campaign_id FROM users WHERE email=%s", (email,))
    u = cur.fetchone()
    if not u or not u['campaign_id']:
        cur.close(); return jsonify({'success': False, 'message': 'No campaign'}), 400
    cid = u['campaign_id']
    cur.execute("SELECT clipper_name, platform, status FROM top_clips WHERE campaign_id=%s AND url=%s LIMIT 1", (cid, clip_url))
    clip = cur.fetchone()
    if not clip:
        cur.close(); return jsonify({'success': False, 'message': 'Clip not found'}), 404
    cur.execute("SELECT id FROM appeals WHERE campaign_id=%s AND clip_url=%s AND status='open'", (cid, clip_url))
    if cur.fetchone():
        cur.close(); return jsonify({'success': False, 'message': 'An appeal is already open for this clip'}), 400
    cur.execute("""INSERT INTO appeals (campaign_id, clip_url, clipper_name, platform, current_status,
                       desired_status, reason, client_email, expires_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (cid, clip_url, clip.get('clipper_name'), clip.get('platform'), clip.get('status'),
                 desired, reason, email, datetime.now() + timedelta(hours=48)))
    mysql.connection.commit()
    cur.close()
    return jsonify({'success': True})

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

    # Report is only available once an admin has set it up (auto or uploaded)
    cur.execute("SELECT mode, pdf_data FROM reports WHERE campaign_id=%s", (d['campaign_id'],))
    rep = cur.fetchone()
    if not rep:
        cur.close()
        return jsonify({'error': 'Report not ready yet'}), 404
    if rep.get('mode') == 'uploaded' and rep.get('pdf_data'):
        import base64
        cur.close()
        b64 = rep['pdf_data'].split(',', 1)[-1]
        buf = BytesIO(base64.b64decode(b64))
        return send_file(buf, as_attachment=True,
                         download_name=f"MagnetiseMedia_Report_{d['campaign_id']}.pdf",
                         mimetype='application/pdf')
    # mode == 'auto' → fall through and generate the PDF below

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