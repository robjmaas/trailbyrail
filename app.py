#!/usr/bin/env python3
import os, sqlite3, math, json
import xml.etree.ElementTree as ET
import requests, stripe
from flask import Flask, request, jsonify, send_from_directory, Response, redirect

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.environ.get('DB_PATH', os.path.join(BASE_DIR, 'trailbytrail.db'))

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

FREE_LIMIT = 20

def init_db():
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
    db.execute('''CREATE TABLE IF NOT EXISTS query_counts (
        ip         TEXT    PRIMARY KEY,
        count      INTEGER DEFAULT 0,
        first_seen TEXT    DEFAULT (datetime('now')),
        last_seen  TEXT    DEFAULT (datetime('now'))
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS pro_ips (
        ip             TEXT    PRIMARY KEY,
        stripe_session TEXT,
        created_at     TEXT    DEFAULT (datetime('now'))
    )''')
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

# ── Search gate ───────────────────────────────────────────────────────────────

@app.route('/api/search-gate', methods=['POST'])
def api_search_gate():
    if cfg('PAYWALL_ENABLED') != '1':
        return jsonify({'ok': True, 'used': 0, 'limit': FREE_LIMIT, 'pro': True})
    ip = client_ip()
    db = get_db()
    # Pro users have unlimited searches
    if db.execute('SELECT 1 FROM pro_ips WHERE ip=?', (ip,)).fetchone():
        db.close()
        return jsonify({'ok': True, 'used': 0, 'limit': FREE_LIMIT, 'pro': True})
    row   = db.execute('SELECT count FROM query_counts WHERE ip=?', (ip,)).fetchone()
    count = row['count'] if row else 0
    if count >= FREE_LIMIT:
        db.close()
        return jsonify({'error': 'limit_reached', 'used': count, 'limit': FREE_LIMIT}), 429
    if row:
        db.execute("UPDATE query_counts SET count=count+1, last_seen=datetime('now') WHERE ip=?", (ip,))
    else:
        db.execute('INSERT INTO query_counts (ip, count) VALUES (?, 1)', (ip,))
    db.commit(); db.close()
    return jsonify({'ok': True, 'used': count + 1, 'limit': FREE_LIMIT, 'pro': False})

# ── Payment ───────────────────────────────────────────────────────────────────

@app.route('/api/checkout', methods=['POST'])
def api_checkout():
    stripe.api_key = cfg('STRIPE_SECRET_KEY')
    price_id       = cfg('STRIPE_PRICE_ID')
    if not stripe.api_key or not price_id:
        return jsonify({'error': 'Payments not configured'}), 503
    host    = request.host_url.rstrip('/')
    session = stripe.checkout.Session.create(
        mode               = 'subscription',
        line_items         = [{'price': price_id, 'quantity': 1}],
        success_url        = f'{host}/payment/success?session_id={{CHECKOUT_SESSION_ID}}',
        cancel_url         = f'{host}/',
        client_reference_id = client_ip(),
    )
    return jsonify({'url': session.url})

@app.route('/payment/success')
def payment_success():
    stripe.api_key = cfg('STRIPE_SECRET_KEY')
    session_id     = request.args.get('session_id', '')
    try:
        session = stripe.checkout.Session.retrieve(session_id)
        if session.payment_status in ('paid', 'no_payment_required'):
            ip = session.client_reference_id or client_ip()
            db = get_db()
            db.execute('INSERT OR REPLACE INTO pro_ips (ip, stripe_session) VALUES (?,?)', (ip, session_id))
            db.commit(); db.close()
    except Exception:
        pass
    return redirect('/?upgraded=1')

# ── Static ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory(BASE_DIR, 'trailconnect.html')

# ── API routes ────────────────────────────────────────────────────────────────

@app.route('/api/overpass', methods=['POST'])
def api_overpass():
    query = request.json.get('query', '')
    r = requests.post(
        'https://overpass-api.de/api/interpreter',
        data={'data': query},
        headers=HEADERS,
        timeout=100,
    )
    if not r.ok:
        return jsonify({'error': f'Overpass error {r.status_code}'}), 502
    return Response(r.content, content_type='application/json')

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
    data = request.json
    url  = (f"https://graphhopper.com/api/1/route"
            f"?point={data['lat']},{data['lon']}"
            f"&algorithm=round_trip"
            f"&round_trip.distance={int(data.get('distance', 10000))}"
            f"&vehicle={data.get('vehicle', 'foot')}"
            f"&locale=en&points_encoded=false"
            f"&key={key}")
    r = requests.get(url, headers=HEADERS, timeout=20)
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

# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    print('🏔️  TrailbyRail\n✅ http://localhost:8080\n')
    app.run(host='0.0.0.0', port=8080, debug=False)
