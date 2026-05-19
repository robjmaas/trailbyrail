#!/usr/bin/env python3
from http.server import HTTPServer, SimpleHTTPRequestHandler
import json, urllib.request, urllib.parse, urllib.error, os, sqlite3, math
import xml.etree.ElementTree as ET

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'trailbytrail.db')

def load_env_file():
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    try:
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, _, v = line.partition('=')
                    os.environ.setdefault(k.strip(), v.strip())
    except FileNotFoundError:
        pass

def load_config():
    load_env_file()
    return {
        'graphhopper_key':   os.environ.get('GRAPHHOPPER_KEY', ''),
        'outdooractive_key': os.environ.get('OUTDOORACTIVE_KEY', ''),
    }

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute('''CREATE TABLE IF NOT EXISTS custom_routes (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        name         TEXT    NOT NULL,
        activity_type TEXT   DEFAULT 'hiking',
        lat          REAL    NOT NULL,
        lon          REAL    NOT NULL,
        dist_km      REAL,
        gpx_data     TEXT    NOT NULL,
        created_at   TEXT    DEFAULT (datetime('now'))
    )''')
    db.commit()
    db.close()

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def haversine_m(lat1, lon1, lat2, lon2):
    R = 6371000
    dl = math.radians(lat2 - lat1)
    do = math.radians(lon2 - lon1)
    a  = math.sin(dl/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(do/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

def parse_gpx(gpx_text):
    """Return (name, lat, lon, dist_km) from a GPX string."""
    try:
        root  = ET.fromstring(gpx_text)
        ns    = root.tag.split('}')[0].strip('{') if '}' in root.tag else ''
        p     = f'{{{ns}}}' if ns else ''
        # name
        name  = None
        for path in [f'{p}metadata/{p}name', f'{p}name']:
            el = root.find(path)
            if el is not None and el.text:
                name = el.text.strip(); break
        # track points
        trkpts = root.findall(f'.//{p}trkpt')
        if trkpts:
            lat = float(trkpts[0].get('lat'))
            lon = float(trkpts[0].get('lon'))
            total = sum(haversine_m(float(trkpts[i-1].get('lat')), float(trkpts[i-1].get('lon')),
                                    float(trkpts[i  ].get('lat')), float(trkpts[i  ].get('lon')))
                        for i in range(1, len(trkpts)))
            dist_km = round(total / 1000, 2) if total > 0 else None
            return name or 'Custom Route', lat, lon, dist_km
        # fallback: waypoints
        wpts = root.findall(f'.//{p}wpt')
        if wpts:
            return name or 'Custom Route', float(wpts[0].get('lat')), float(wpts[0].get('lon')), None
    except Exception:
        pass
    return None, None, None, None

def send_json(handler, obj, status=200):
    body = json.dumps(obj).encode()
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json')
    handler.send_header('Access-Control-Allow-Origin', '*')
    handler.end_headers()
    handler.wfile.write(body)

def send_raw(handler, body, content_type, disposition=None):
    handler.send_response(200)
    handler.send_header('Content-Type', content_type)
    if disposition:
        handler.send_header('Content-Disposition', disposition)
    handler.send_header('Access-Control-Allow-Origin', '*')
    handler.end_headers()
    handler.wfile.write(body)

class TrailHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path in ['/', '/index.html']:
            self.path = '/trailconnect.html'
        return SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers['Content-Length'])).decode('utf-8'))
        try:
            self._route(data)
        except Exception as e:
            send_json(self, {'error': str(e)}, 500)

    def _route(self, data):
        p = self.path

        # ── Overpass ──────────────────────────────────────────────────────────
        if p == '/api/overpass':
            query = data.get('query', '')
            body  = f'data={urllib.parse.quote(query)}'.encode()
            req   = urllib.request.Request('https://overpass-api.de/api/interpreter',
                data=body,
                headers={'Content-Type':'application/x-www-form-urlencoded','User-Agent':'TrailbyRail/1.0'})
            try:
                send_raw(self, urllib.request.urlopen(req, timeout=100).read(), 'application/json')
            except urllib.error.HTTPError as e:
                send_json(self, {'error': f'Overpass error {e.code}'}, 502)

        # ── Geocode ───────────────────────────────────────────────────────────
        elif p == '/api/geocode':
            url = (f"https://nominatim.openstreetmap.org/search"
                   f"?format=json&q={urllib.parse.quote(data.get('location',''))}&limit=1")
            send_raw(self, urllib.request.urlopen(
                urllib.request.Request(url, headers={'User-Agent':'TrailbyRail/1.0'}), timeout=10).read(),
                'application/json')

        # ── Waymarked Trails ──────────────────────────────────────────────────
        elif p == '/api/waymarked-trails':
            bases = {'hiking':'https://hiking.waymarkedtrails.org/api/v1',
                     'cycling':'https://cycling.waymarkedtrails.org/api/v1',
                     'mtb':'https://mtb.waymarkedtrails.org/api/v1'}
            base = bases.get(data.get('route_type','hiking'), bases['hiking'])
            t    = data.get('type','search')
            if t == 'search':
                url = f"{base}/list/search?bbox={data.get('bbox','')}"
                send_raw(self, urllib.request.urlopen(urllib.request.Request(
                    url, headers={'User-Agent':'TrailbyRail/1.0'}), timeout=30).read(), 'application/json')
            elif t == 'details':
                url = f"{base}/details/relation/{data.get('id','')}"
                send_raw(self, urllib.request.urlopen(urllib.request.Request(
                    url, headers={'User-Agent':'TrailbyRail/1.0'}), timeout=15).read(), 'application/json')
            elif t == 'gpx':
                url = f"{base}/details/relation/{data.get('id','')}/gpx"
                send_raw(self, urllib.request.urlopen(urllib.request.Request(
                    url, headers={'User-Agent':'TrailbyRail/1.0'}), timeout=30).read(),
                    'application/gpx+xml', f'attachment; filename="route_{data.get("id","")}.gpx"')
            else:
                raise ValueError(f"Unknown waymarked type: {t}")

        # ── Outdooractive ─────────────────────────────────────────────────────
        elif p == '/api/outdooractive':
            key = load_config().get('outdooractive_key', '')
            if not key: raise ValueError('OUTDOORACTIVE_KEY not configured on server')
            url = (f"https://www.outdooractive.com/api/odr/tours"
                   f"?key={urllib.parse.quote(key)}&lat={data['lat']}&lng={data['lon']}"
                   f"&radius={data.get('radius',10)}&cat={urllib.parse.quote(data.get('cat','hiking'))}"
                   f"&limit={data.get('limit',20)}&lang=en")
            send_raw(self, urllib.request.urlopen(urllib.request.Request(
                url, headers={'User-Agent':'TrailbyRail/1.0','Accept':'application/json'}),
                timeout=15).read(), 'application/json')

        # ── GraphHopper round-trip ────────────────────────────────────────────
        elif p == '/api/graphhopper':
            key = load_config().get('graphhopper_key', '')
            if not key: raise ValueError('GRAPHHOPPER_KEY not configured on server')
            url = (f"https://graphhopper.com/api/1/route"
                   f"?point={data['lat']},{data['lon']}"
                   f"&algorithm=round_trip"
                   f"&round_trip.distance={int(data.get('distance', 10000))}"
                   f"&vehicle={data.get('vehicle','foot')}"
                   f"&locale=en&points_encoded=false"
                   f"&key={urllib.parse.quote(key)}")
            send_raw(self, urllib.request.urlopen(urllib.request.Request(
                url, headers={'User-Agent':'TrailbyRail/1.0'}), timeout=20).read(), 'application/json')

        # ── Upload GPX ────────────────────────────────────────────────────────
        elif p == '/api/upload-gpx':
            gpx_text = data.get('gpx','')
            if not gpx_text: raise ValueError('No GPX data')
            name, lat, lon, dist_km = parse_gpx(gpx_text)
            if lat is None: raise ValueError('Could not parse GPX coordinates')
            name = data.get('name','').strip() or name or 'Custom Route'
            db   = get_db()
            cur  = db.execute(
                'INSERT INTO custom_routes (name,activity_type,lat,lon,dist_km,gpx_data) VALUES (?,?,?,?,?,?)',
                (name, data.get('activity_type','hiking'), lat, lon, dist_km, gpx_text))
            db.commit(); db.close()
            send_json(self, {'id': cur.lastrowid, 'name': name, 'lat': lat, 'lon': lon, 'dist_km': dist_km})

        # ── Custom routes (list / search / get-gpx / delete) ─────────────────
        elif p == '/api/custom-routes':
            action = data.get('action','list')
            db = get_db()
            if action == 'delete':
                db.execute('DELETE FROM custom_routes WHERE id=?', (data['id'],))
                db.commit(); db.close()
                send_json(self, {'ok': True})
            elif action == 'get-gpx':
                row = db.execute('SELECT gpx_data, name FROM custom_routes WHERE id=?',
                                 (data['id'],)).fetchone()
                db.close()
                if not row: raise ValueError('Route not found')
                fname = row['name'].replace(' ','_').replace('/','_')
                send_raw(self, row['gpx_data'].encode('utf-8'), 'application/gpx+xml',
                         f'attachment; filename="{fname}.gpx"')
            else:
                rows = db.execute(
                    'SELECT id,name,activity_type,lat,lon,dist_km,created_at FROM custom_routes ORDER BY created_at DESC'
                ).fetchall()
                db.close()
                routes = [dict(r) for r in rows]
                if 'lat' in data and 'lon' in data:
                    r_m = data.get('radius_m', 50000)
                    routes = [r for r in routes
                              if haversine_m(data['lat'], data['lon'], r['lat'], r['lon']) <= r_m]
                send_json(self, routes)

        else:
            send_json(self, {'error': f'Unknown endpoint: {self.path}'}, 404)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin','*')
        self.send_header('Access-Control-Allow-Methods','GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers','Content-Type')
        self.end_headers()

    def log_message(self, fmt, *args):
        pass  # silence request logs

if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    init_db()
    print('🏔️  TrailbyRail\n✅ http://localhost:8080\n')
    HTTPServer(('', 8080), TrailHandler).serve_forever()
