#!/usr/bin/env python3
import os, sqlite3, math, json, threading, time
import xml.etree.ElementTree as ET
import requests
from flask import Flask, request, jsonify, send_from_directory, Response, redirect
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_default_db = '/data/trailbytrail.db' if os.path.isdir('/data') else os.path.join(BASE_DIR, 'trailbytrail.db')
DB_PATH      = os.environ.get('DB_PATH', _default_db)
FREE_SEARCHES = int(os.environ.get('FREE_SEARCHES', '5'))

app = Flask(__name__, static_folder=BASE_DIR, static_url_path='')

# ── Env / config ──────────────────────────────────────────────────────────────

def load_env_file():
    env_path = os.path.join(BASE_DIR, '.env')
    try:
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, _, v = line.partition('=')
                    os.environ.setdefault(k.strip(), v.strip())
    except FileNotFoundError:
        pass

load_env_file()

def cfg(key):
    return os.environ.get(key, '')

def client_ip():
    forwarded = request.headers.get('X-Forwarded-For', '')
    return forwarded.split(',')[0].strip() if forwarded else request.remote_addr

# ── Database ──────────────────────────────────────────────────────────────────

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.execute('''CREATE TABLE IF NOT EXISTS custom_routes (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        name          TEXT    NOT NULL,
        activity_type TEXT    DEFAULT 'hiking',
        lat           REAL    NOT NULL,
        lon           REAL    NOT NULL,
        dist_km       REAL,
        gpx_data      TEXT    NOT NULL,
        created_at    TEXT    DEFAULT (datetime('now'))
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS reviews (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        trail_id   TEXT    NOT NULL,
        trail_name TEXT    NOT NULL,
        rating     INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
        comment    TEXT,
        ip         TEXT,
        user_id    INTEGER,
        created_at TEXT    DEFAULT (datetime('now'))
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS users (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        email             TEXT    NOT NULL UNIQUE,
        password_hash     TEXT    NOT NULL,
        is_pro            INTEGER DEFAULT 0,
        stripe_customer_id TEXT,
        created_at        TEXT    DEFAULT (datetime('now'))
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS user_sessions (
        token      TEXT    PRIMARY KEY,
        user_id    INTEGER NOT NULL REFERENCES users(id),
        created_at TEXT    DEFAULT (datetime('now'))
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS user_done_trails (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL REFERENCES users(id),
        trail_name TEXT    NOT NULL,
        trail_lat  REAL,
        trail_lon  REAL,
        done_at    TEXT    DEFAULT (datetime('now')),
        UNIQUE(user_id, trail_name)
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS user_saved_searches (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER NOT NULL REFERENCES users(id),
        label      TEXT    NOT NULL,
        data       TEXT    NOT NULL,
        created_at TEXT    DEFAULT (datetime('now'))
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS guest_searches (
        ip         TEXT PRIMARY KEY,
        count      INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT    DEFAULT (datetime('now'))
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS share_links (
        code       TEXT PRIMARY KEY,
        data       TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
    )''')
    # Migration: add search_count to users if it doesn't exist yet
    try:
        db.execute('ALTER TABLE users ADD COLUMN search_count INTEGER DEFAULT 0')
    except Exception:
        pass
    db.commit()
    db.close()

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

# ── Helpers ───────────────────────────────────────────────────────────────────

HEADERS = {'User-Agent': 'TrailbyRail/1.0'}

def haversine_m(lat1, lon1, lat2, lon2):
    R  = 6371000
    dl = math.radians(lat2 - lat1)
    do = math.radians(lon2 - lon1)
    a  = math.sin(dl/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(do/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

def parse_gpx(gpx_text):
    try:
        root   = ET.fromstring(gpx_text)
        ns     = root.tag.split('}')[0].strip('{') if '}' in root.tag else ''
        p      = f'{{{ns}}}' if ns else ''
        name   = None
        for path in [f'{p}metadata/{p}name', f'{p}name']:
            el = root.find(path)
            if el is not None and el.text:
                name = el.text.strip(); break
        trkpts = root.findall(f'.//{p}trkpt')
        if trkpts:
            lat   = float(trkpts[0].get('lat'))
            lon   = float(trkpts[0].get('lon'))
            total = sum(haversine_m(float(trkpts[i-1].get('lat')), float(trkpts[i-1].get('lon')),
                                    float(trkpts[i  ].get('lat')), float(trkpts[i  ].get('lon')))
                        for i in range(1, len(trkpts)))
            return name or 'Custom Route', lat, lon, round(total / 1000, 2) if total > 0 else None
        wpts = root.findall(f'.//{p}wpt')
        if wpts:
            return name or 'Custom Route', float(wpts[0].get('lat')), float(wpts[0].get('lon')), None
    except Exception:
        pass
    return None, None, None, None

def proxy(url, *, timeout=30, content_type='application/json', disposition=None):
    r = requests.get(url, headers=HEADERS, timeout=timeout)
    r.raise_for_status()
    headers = {'Content-Type': content_type}
    if disposition:
        headers['Content-Disposition'] = disposition
    return Response(r.content, headers=headers)

# ── Auth helper ───────────────────────────────────────────────────────────────

def get_current_user():
    token = request.cookies.get('session_token')
    if not token:
        return None
    db = get_db()
    row = db.execute(
        'SELECT u.* FROM users u JOIN user_sessions s ON s.user_id=u.id WHERE s.token=?', (token,)
    ).fetchone()
    db.close()
    return dict(row) if row else None

# ── Auth endpoints ────────────────────────────────────────────────────────────

@app.route('/api/auth/register', methods=['POST'])
def api_auth_register():
    data     = request.json or {}
    email    = data.get('email', '').strip().lower()
    password = data.get('password', '')
    if '@' not in email:
        return jsonify({'error': 'Invalid email'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    db = get_db()
    if db.execute('SELECT 1 FROM users WHERE email=?', (email,)).fetchone():
        db.close()
        return jsonify({'error': 'Email already registered'}), 409
    pw_hash = generate_password_hash(password)
    cur = db.execute('INSERT INTO users (email, password_hash) VALUES (?,?)', (email, pw_hash))
    user_id = cur.lastrowid
    token = secrets.token_hex(32)
    db.execute('INSERT INTO user_sessions (token, user_id) VALUES (?,?)', (token, user_id))
    db.commit(); db.close()
    resp = jsonify({'ok': True, 'email': email, 'id': user_id})
    resp.set_cookie('session_token', token, httponly=True, samesite='Lax', secure=True, max_age=90*24*3600)
    return resp

@app.route('/api/auth/login', methods=['POST'])
def api_auth_login():
    data     = request.json or {}
    email    = data.get('email', '').strip().lower()
    password = data.get('password', '')
    db = get_db()
    row = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    if not row:
        db.close()
        return jsonify({'error': 'No account found with that email'}), 401
    if not check_password_hash(row['password_hash'], password):
        db.close()
        return jsonify({'error': 'Incorrect password'}), 401
    token = secrets.token_hex(32)
    db.execute('INSERT INTO user_sessions (token, user_id) VALUES (?,?)', (token, row['id']))
    db.commit(); db.close()
    resp = jsonify({'ok': True, 'email': row['email'], 'id': row['id'], 'is_pro': row['is_pro']})
    resp.set_cookie('session_token', token, httponly=True, samesite='Lax', secure=True, max_age=90*24*3600)
    return resp

@app.route('/api/auth/logout', methods=['POST'])
def api_auth_logout():
    token = request.cookies.get('session_token')
    if token:
        db = get_db()
        db.execute('DELETE FROM user_sessions WHERE token=?', (token,))
        db.commit(); db.close()
    resp = jsonify({'ok': True})
    resp.delete_cookie('session_token')
    return resp

@app.route('/api/auth/me', methods=['GET'])
def api_auth_me():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify({'id': user['id'], 'email': user['email'], 'is_pro': user['is_pro']})

# ── Done trails endpoints ─────────────────────────────────────────────────────

@app.route('/api/done-trails', methods=['GET'])
def api_done_trails_get():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    db = get_db()
    rows = db.execute(
        'SELECT trail_name, done_at FROM user_done_trails WHERE user_id=? ORDER BY done_at DESC',
        (user['id'],)
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/done-trails', methods=['POST'])
def api_done_trails_post():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    data       = request.json or {}
    trail_name = data.get('trail_name', '').strip()
    action     = data.get('action', 'add')
    if not trail_name:
        return jsonify({'error': 'trail_name required'}), 400
    db = get_db()
    if action == 'remove':
        db.execute('DELETE FROM user_done_trails WHERE user_id=? AND trail_name=?',
                   (user['id'], trail_name))
    else:
        trail_lat = data.get('trail_lat')
        trail_lon = data.get('trail_lon')
        db.execute(
            'INSERT OR IGNORE INTO user_done_trails (user_id, trail_name, trail_lat, trail_lon) VALUES (?,?,?,?)',
            (user['id'], trail_name, trail_lat, trail_lon)
        )
    db.commit(); db.close()
    return jsonify({'ok': True})

# ── Saved searches endpoints ──────────────────────────────────────────────────

@app.route('/api/saved-searches', methods=['GET'])
def api_saved_searches_get():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    db = get_db()
    rows = db.execute(
        'SELECT id, label, data, created_at FROM user_saved_searches WHERE user_id=? ORDER BY created_at DESC',
        (user['id'],)
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/saved-searches', methods=['POST'])
def api_saved_searches_post():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    data   = request.json or {}
    action = data.get('action', 'save')
    db = get_db()
    if action == 'delete':
        db.execute('DELETE FROM user_saved_searches WHERE id=? AND user_id=?',
                   (data.get('id'), user['id']))
    else:
        label = data.get('label', '').strip()
        sdata = data.get('data', '')
        if not label:
            db.close()
            return jsonify({'error': 'label required'}), 400
        count = db.execute(
            'SELECT COUNT(*) FROM user_saved_searches WHERE user_id=?', (user['id'],)
        ).fetchone()[0]
        if count >= 10:
            db.close()
            return jsonify({'error': 'Max 10 saved searches'}), 400
        db.execute(
            'INSERT INTO user_saved_searches (user_id, label, data) VALUES (?,?,?)',
            (user['id'], label, sdata if isinstance(sdata, str) else json.dumps(sdata))
        )
    db.commit(); db.close()
    return jsonify({'ok': True})

# ── Short share links ─────────────────────────────────────────────────────────

@app.route('/api/share', methods=['POST'])
def api_share_create():
    params = request.json or {}
    if not params:
        return jsonify({'error': 'No params'}), 400
    db = get_db()
    # Generate a unique 6-char URL-safe code
    for _ in range(10):
        code = secrets.token_urlsafe(4)[:6]
        if not db.execute('SELECT 1 FROM share_links WHERE code=?', (code,)).fetchone():
            break
    db.execute('INSERT OR REPLACE INTO share_links (code, data) VALUES (?,?)',
               (code, json.dumps(params)))
    db.commit(); db.close()
    return jsonify({'code': code})

@app.route('/api/share/<code>', methods=['GET'])
def api_share_get(code):
    db = get_db()
    row = db.execute('SELECT data FROM share_links WHERE code=?', (code,)).fetchone()
    db.close()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    return Response(row['data'], content_type='application/json')

@app.route('/s/<code>')
def share_page(code):
    # Serve the SPA — JS will detect the /s/ path and fetch params
    return send_from_directory(BASE_DIR, 'trailconnect.html')

# ── Admin / debug ─────────────────────────────────────────────────────────────

def _admin_check():
    key = request.args.get('key', '')
    admin_key = cfg('ADMIN_KEY')
    return admin_key and key == admin_key

@app.route('/api/admin/status', methods=['GET'])
def api_admin_status():
    if not _admin_check():
        return jsonify({'error': 'Forbidden'}), 403
    db = get_db()
    users  = db.execute('SELECT id, email, search_count, created_at FROM users ORDER BY id').fetchall()
    guests = db.execute('SELECT ip, count, updated_at FROM guest_searches ORDER BY count DESC LIMIT 20').fetchall()
    db.close()
    return jsonify({
        'db_path':      DB_PATH,
        'db_exists':    os.path.isfile(DB_PATH),
        'free_searches': FREE_SEARCHES,
        'users':  [dict(u) for u in users],
        'top_guests': [dict(g) for g in guests],
    })

@app.route('/api/admin/create-user', methods=['POST'])
def api_admin_create_user():
    if not _admin_check():
        return jsonify({'error': 'Forbidden'}), 403
    data     = request.json or {}
    email    = data.get('email', '').strip().lower()
    password = data.get('password', '')
    if '@' not in email or len(password) < 8:
        return jsonify({'error': 'Invalid email or password too short'}), 400
    db = get_db()
    existing = db.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()
    if existing:
        # Update password for existing account
        db.execute('UPDATE users SET password_hash=? WHERE email=?',
                   (generate_password_hash(password), email))
        db.commit(); db.close()
        return jsonify({'ok': True, 'action': 'password_updated', 'email': email})
    cur = db.execute('INSERT INTO users (email, password_hash) VALUES (?,?)',
                     (email, generate_password_hash(password)))
    db.commit(); db.close()
    return jsonify({'ok': True, 'action': 'created', 'email': email, 'id': cur.lastrowid})

# ── Search tracking ──────────────────────────────────────────────────────────

@app.route('/api/track-search', methods=['POST'])
def api_track_search():
    user = get_current_user()
    ip   = client_ip()
    db   = get_db()
    if user:
        db.execute('UPDATE users SET search_count = search_count + 1 WHERE id=?', (user['id'],))
        row   = db.execute('SELECT search_count FROM users WHERE id=?', (user['id'],)).fetchone()
        count = row['search_count'] if row else 1
        db.commit(); db.close()
        return jsonify({'count': count, 'limit': None, 'requires_signup': False})
    else:
        db.execute('''
            INSERT INTO guest_searches (ip, count, updated_at) VALUES (?, 1, datetime('now'))
            ON CONFLICT(ip) DO UPDATE SET count = count + 1, updated_at = datetime('now')
        ''', (ip,))
        row   = db.execute('SELECT count FROM guest_searches WHERE ip=?', (ip,)).fetchone()
        count = row['count'] if row else 1
        db.commit(); db.close()
        return jsonify({'count': count, 'limit': FREE_SEARCHES,
                        'requires_signup': count > FREE_SEARCHES})

# ── Global error handlers — always return JSON, never HTML ───────────────────

@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, requests.HTTPError):
        return jsonify({'error': f'Upstream error {e.response.status_code}'}), 502
    return jsonify({'error': str(e)}), 500

# ── Static ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory(BASE_DIR, 'trailconnect.html')

# ── API routes ────────────────────────────────────────────────────────────────

OVERPASS_ENDPOINTS = [
    'https://overpass-api.de/api/interpreter',
    'https://overpass.kumi.systems/api/interpreter',
    'https://maps.mail.ru/osm/tools/overpass/api/interpreter',
]

# Serialize Overpass calls so two parallel requests from the same Railway IP
# don't both hit the rate limit simultaneously.
_overpass_lock = threading.Lock()
_overpass_last_call = [0.0]   # list so the closure can mutate it
_OVERPASS_MIN_GAP = 3.0       # seconds between outbound requests — conservative to avoid bans

@app.route('/api/overpass', methods=['POST'])
def api_overpass():
    query = request.json.get('query', '')
    with _overpass_lock:
        wait = _OVERPASS_MIN_GAP - (time.time() - _overpass_last_call[0])
        if wait > 0:
            time.sleep(wait)
        _overpass_last_call[0] = time.time()

    last_err = None
    for i, endpoint in enumerate(OVERPASS_ENDPOINTS):
        try:
            if i > 0:
                time.sleep(3.0)   # wait longer before trying next mirror
            r = requests.post(
                endpoint,
                data={'data': query},
                headers=HEADERS,
                timeout=55,
            )
            if r.status_code in (429, 403):
                last_err = r.status_code
                continue          # try next mirror on rate-limit or block
            if not r.ok:
                last_err = r.status_code
                continue
            return Response(r.content, content_type='application/json')
        except requests.Timeout:
            last_err = 'timeout'
            continue
        except Exception as e:
            last_err = str(e)
            continue
    if last_err in (429, 403):
        return jsonify({'error': f'Overpass error {last_err}'}), 429
    if last_err == 'timeout':
        return jsonify({'error': 'Overpass error 504'}), 504
    return jsonify({'error': f'Overpass error {last_err}'}), 502

@app.route('/api/geocode', methods=['POST'])
def api_geocode():
    q   = request.json.get('location', '')
    url = f'https://nominatim.openstreetmap.org/search?format=json&q={requests.utils.quote(q)}&limit=1'
    return proxy(url, timeout=10)

@app.route('/api/waymarked-trails', methods=['POST'])
def api_waymarked():
    data  = request.json
    bases = {
        'hiking':  'https://hiking.waymarkedtrails.org/api/v1',
        'cycling': 'https://cycling.waymarkedtrails.org/api/v1',
        'mtb':     'https://mtb.waymarkedtrails.org/api/v1',
    }
    base = bases.get(data.get('route_type', 'hiking'), bases['hiking'])
    t    = data.get('type', 'search')
    if t == 'search':
        return proxy(f"{base}/list/search?bbox={data.get('bbox','')}", timeout=30)
    elif t == 'details':
        return proxy(f"{base}/details/relation/{data.get('id','')}", timeout=15)
    elif t == 'gpx':
        rid = data.get('id', '')
        return proxy(f"{base}/details/relation/{rid}/gpx", timeout=30,
                     content_type='application/gpx+xml',
                     disposition=f'attachment; filename="route_{rid}.gpx"')
    return jsonify({'error': 'Unknown waymarked type'}), 400

@app.route('/api/outdooractive', methods=['POST'])
def api_outdooractive():
    key = cfg('OUTDOORACTIVE_KEY')
    if not key:
        return jsonify({'error': 'OUTDOORACTIVE_KEY not configured'}), 503
    data = request.json
    url  = (f"https://www.outdooractive.com/api/odr/tours"
            f"?key={key}&lat={data['lat']}&lng={data['lon']}"
            f"&radius={data.get('radius', 10)}&cat={requests.utils.quote(data.get('cat','hiking'))}"
            f"&limit={data.get('limit', 20)}&lang=en")
    r = requests.get(url, headers={**HEADERS, 'Accept': 'application/json'}, timeout=15)
    r.raise_for_status()
    return Response(r.content, content_type='application/json')

@app.route('/api/graphhopper', methods=['POST'])
def api_graphhopper():
    key = cfg('GRAPHHOPPER_KEY')
    if not key:
        return jsonify({'error': 'GRAPHHOPPER_KEY not configured'}), 503
    data    = request.json
    profile = data.get('vehicle', 'hike')   # hike > foot: prefers designated trails
    is_foot  = profile in ('foot', 'hike')
    is_cycle = profile in ('bike', 'mtb', 'racingbike')

    body = {
        'points':         [[data['lon'], data['lat']]],  # GH expects [lon, lat]
        'profile':        profile,
        'algorithm':      'round_trip',
        'round_trip':     {'distance': int(data.get('distance', 10000)), 'seed': 0},
        'locale':         'en',
        'points_encoded': False,
        'ch.disable':     True,   # required for custom_model
    }

    # For foot/hike: strongly prefer tracks, paths and unpaved surfaces
    if is_foot:
        body['custom_model'] = {
            'priority': [
                {'if': 'road_class == TRACK',    'multiply_by': 3.0},
                {'if': 'road_class == FOOTWAY',  'multiply_by': 2.5},
                {'if': 'road_class == BRIDLEWAY','multiply_by': 2.5},
                {'if': 'road_class == PATH',     'multiply_by': 3.0},
                {'if': 'road_class == RESIDENTIAL || road_class == SERVICE || road_class == UNCLASSIFIED',
                 'multiply_by': 0.5},
                {'if': 'road_class == TERTIARY', 'multiply_by': 0.3},
                {'if': 'road_class == SECONDARY','multiply_by': 0.15},
                {'if': 'road_class == PRIMARY || road_class == TRUNK || road_class == MOTORWAY',
                 'multiply_by': 0.02},
            ]
        }

    # For cycling: strongly prefer cycleways, tracks and paths over roads
    if is_cycle:
        body['custom_model'] = {
            'priority': [
                {'if': 'road_class == CYCLEWAY',  'multiply_by': 3.0},
                {'if': 'road_class == TRACK',     'multiply_by': 2.5},
                {'if': 'road_class == PATH',      'multiply_by': 2.0},
                {'if': 'road_class == BRIDLEWAY', 'multiply_by': 1.8},
                {'if': 'road_class == RESIDENTIAL || road_class == SERVICE || road_class == UNCLASSIFIED',
                 'multiply_by': 0.5},
                {'if': 'road_class == TERTIARY',  'multiply_by': 0.4},
                {'if': 'road_class == SECONDARY', 'multiply_by': 0.2},
                {'if': 'road_class == PRIMARY || road_class == TRUNK || road_class == MOTORWAY',
                 'multiply_by': 0.05},
            ]
        }

    r = requests.post(
        f'https://graphhopper.com/api/1/route?key={key}',
        json=body,
        headers={**HEADERS, 'Content-Type': 'application/json'},
        timeout=25,
    )
    r.raise_for_status()
    return Response(r.content, content_type='application/json')

@app.route('/api/upload-gpx', methods=['POST'])
def api_upload_gpx():
    data     = request.json
    gpx_text = data.get('gpx', '')
    if not gpx_text:
        return jsonify({'error': 'No GPX data'}), 400
    name, lat, lon, dist_km = parse_gpx(gpx_text)
    if lat is None:
        return jsonify({'error': 'Could not parse GPX coordinates'}), 400
    name = data.get('name', '').strip() or name or 'Custom Route'
    db   = get_db()
    cur  = db.execute(
        'INSERT INTO custom_routes (name,activity_type,lat,lon,dist_km,gpx_data) VALUES (?,?,?,?,?,?)',
        (name, data.get('activity_type', 'hiking'), lat, lon, dist_km, gpx_text))
    db.commit(); db.close()
    return jsonify({'id': cur.lastrowid, 'name': name, 'lat': lat, 'lon': lon, 'dist_km': dist_km})

@app.route('/api/custom-routes', methods=['POST'])
def api_custom_routes():
    data   = request.json
    action = data.get('action', 'list')
    db     = get_db()
    if action == 'delete':
        db.execute('DELETE FROM custom_routes WHERE id=?', (data['id'],))
        db.commit(); db.close()
        return jsonify({'ok': True})
    elif action == 'get-gpx':
        row = db.execute('SELECT gpx_data, name FROM custom_routes WHERE id=?',
                         (data['id'],)).fetchone()
        db.close()
        if not row:
            return jsonify({'error': 'Route not found'}), 404
        fname = row['name'].replace(' ', '_').replace('/', '_')
        return Response(row['gpx_data'].encode('utf-8'),
                        content_type='application/gpx+xml',
                        headers={'Content-Disposition': f'attachment; filename="{fname}.gpx"'})
    else:
        rows   = db.execute(
            'SELECT id,name,activity_type,lat,lon,dist_km,created_at FROM custom_routes ORDER BY created_at DESC'
        ).fetchall()
        db.close()
        routes = [dict(r) for r in rows]
        if 'lat' in data and 'lon' in data:
            r_m    = data.get('radius_m', 50000)
            routes = [r for r in routes
                      if haversine_m(data['lat'], data['lon'], r['lat'], r['lon']) <= r_m]
        return jsonify(routes)

@app.route('/api/weather', methods=['POST'])
def api_weather():
    data = request.json
    url  = (f"https://api.open-meteo.com/v1/forecast"
            f"?latitude={data['lat']}&longitude={data['lon']}"
            f"&daily=weathercode,temperature_2m_max,temperature_2m_min,precipitation_sum"
            f"&forecast_days=3&timezone=auto")
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    return Response(r.content, content_type='application/json')

@app.route('/api/reviews', methods=['POST'])
def api_reviews():
    trail_id = request.json.get('trail_id', '')
    db = get_db()
    rows = db.execute(
        'SELECT rating, comment, created_at FROM reviews WHERE trail_id=? ORDER BY created_at DESC',
        (trail_id,)
    ).fetchall()
    avg_row = db.execute(
        'SELECT AVG(rating) as avg, COUNT(*) as cnt FROM reviews WHERE trail_id=?',
        (trail_id,)
    ).fetchone()
    db.close()
    return jsonify({
        'reviews': [dict(r) for r in rows],
        'avg': round(avg_row['avg'], 1) if avg_row['avg'] else None,
        'count': avg_row['cnt']
    })

@app.route('/api/review-add', methods=['POST'])
def api_review_add():
    data = request.json
    trail_id   = data.get('trail_id', '').strip()
    trail_name = data.get('trail_name', '').strip()
    rating     = int(data.get('rating', 0))
    comment    = data.get('comment', '').strip()
    if not trail_id or not 1 <= rating <= 5:
        return jsonify({'error': 'Invalid data'}), 400
    user = get_current_user()
    user_id = user['id'] if user else None
    db = get_db()
    cur = db.execute(
        'INSERT INTO reviews (trail_id, trail_name, rating, comment, ip, user_id) VALUES (?,?,?,?,?,?)',
        (trail_id, trail_name, rating, comment, client_ip(), user_id)
    )
    db.commit()
    db.close()
    return jsonify({'ok': True, 'id': cur.lastrowid})

# ── Run ───────────────────────────────────────────────────────────────────────

init_db()  # runs on every startup — gunicorn workers included

if __name__ == '__main__':
    print('🏔️  TrailbyRail\n✅ http://localhost:8080\n')
    app.run(host='0.0.0.0', port=8080, debug=False)
