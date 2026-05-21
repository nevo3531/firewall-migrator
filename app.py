"""
FireWall Migrator Pro — Main Application
PyInstaller-compatible single-file Flask server
"""

import sys
import os
import json
import traceback
import tempfile
import threading
import webbrowser
import time
import socket
import argparse

# ── PyInstaller path fix ──────────────────────────────────────────────────────
if getattr(sys, 'frozen', False):
    # Running as compiled EXE
    BASE_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, BASE_DIR)

from flask import Flask, request, jsonify, Response
from flask_cors import CORS

# Local modules
from fw_migrator.fortigate_connector import FortiGateConnector
from fw_migrator.checkpoint_connector import CheckpointConnector
from fw_migrator.fortigate_parser import FortiGateParser
from fw_migrator.checkpoint_parser import CheckpointParser
from fw_migrator.checkpoint_to_forti import CheckpointToFortiConverter
from fw_migrator.forti_to_forti import FortiToFortiConverter

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), 'fw_migrator')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ── Load embedded HTML ────────────────────────────────────────────────────────
def load_ui():
    ui_path = os.path.join(BASE_DIR, 'fw_migrator', 'ui.html')
    if os.path.exists(ui_path):
        with open(ui_path, encoding='utf-8') as f:
            return f.read()
    return '<h1>UI not found</h1>'

UI_HTML = None  # lazy-loaded

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    global UI_HTML
    if UI_HTML is None:
        UI_HTML = load_ui()
    return UI_HTML, 200, {'Content-Type': 'text/html; charset=utf-8'}


@app.route('/api/test-connection', methods=['POST'])
def test_connection():
    data = request.json or {}
    source_type = data.get('source_type', '')
    gateway  = data.get('gateway', '')
    username = data.get('username', '')
    password = data.get('password', '')
    port     = data.get('port', 22)
    try:
        if source_type == 'fortigate':
            conn = FortiGateConnector(gateway, username, password, port)
        elif source_type == 'checkpoint':
            conn = CheckpointConnector(gateway, username, password, port)
        else:
            return jsonify({'success': False, 'error': 'Unknown source type'})
        return jsonify(conn.test_connection())
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/download-config', methods=['POST'])
def download_config():
    data = request.json or {}
    source_type = data.get('source_type', '')
    gateway  = data.get('gateway', '')
    username = data.get('username', '')
    password = data.get('password', '')
    port     = data.get('port', 22)
    try:
        if source_type == 'fortigate':
            conn   = FortiGateConnector(gateway, username, password, port)
            raw    = conn.download_config()
            parser = FortiGateParser()
        elif source_type == 'checkpoint':
            conn   = CheckpointConnector(gateway, username, password, port)
            raw    = conn.download_config()
            parser = CheckpointParser()
        else:
            return jsonify({'success': False, 'error': 'Unknown source type'})

        parsed  = parser.parse(raw)
        summary = parser.get_summary(parsed)
        cfg_id  = f'cfg_{gateway.replace(".", "_")}'
        cfg_path = os.path.join(UPLOAD_FOLDER, f'{cfg_id}.json')
        with open(cfg_path, 'w', encoding='utf-8') as f:
            json.dump({'raw': raw, 'parsed': parsed}, f)

        preview = raw[:600] if isinstance(raw, str) else str(raw)[:600]
        return jsonify({'success': True, 'summary': summary,
                        'config_id': cfg_id, 'raw_preview': preview})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/upload-config', methods=['POST'])
def upload_config():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'})
    file = request.files['file']
    source_type = request.form.get('source_type', 'fortigate')
    content = file.read().decode('utf-8', errors='replace')
    try:
        parser = FortiGateParser() if source_type == 'fortigate' else CheckpointParser()
        parsed  = parser.parse(content)
        summary = parser.get_summary(parsed)
        cfg_id  = f'upload_{file.filename.replace(".", "_").replace(" ", "_")}'
        cfg_path = os.path.join(UPLOAD_FOLDER, f'{cfg_id}.json')
        with open(cfg_path, 'w', encoding='utf-8') as f:
            json.dump({'raw': content, 'parsed': parsed}, f)
        return jsonify({'success': True, 'summary': summary,
                        'config_id': cfg_id, 'raw_preview': content[:600]})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/analyze-config', methods=['POST'])
def analyze_config():
    data = request.json or {}
    cfg_id = data.get('config_id', '')
    migration_type = data.get('migration_type', '')
    cfg_path = os.path.join(UPLOAD_FOLDER, f'{cfg_id}.json')
    if not os.path.exists(cfg_path):
        return jsonify({'success': False, 'error': 'Config not found'})
    with open(cfg_path, encoding='utf-8') as f:
        cfg_data = json.load(f)
    parsed = cfg_data.get('parsed', {})
    info, warnings, errors = [], [], []

    policies   = parsed.get('policies', [])
    objects    = parsed.get('objects', {})
    interfaces = parsed.get('interfaces', [])
    addresses  = objects.get('addresses', [])
    services   = objects.get('services', [])

    info.append(f'נמצאו {len(policies)} פוליסות')
    info.append(f'נמצאו {len(interfaces)} ממשקים')
    info.append(f'נמצאו {len(addresses)} כתובות ו-{len(services)} שירותים')
    info.append(f'נמצאו {len(parsed.get("routes",[]))} static routes')

    for p in policies:
        src = str(p.get('src', ''))
        dst = str(p.get('dst', ''))
        if src.lower() in ('any', 'all') and dst.lower() in ('any', 'all'):
            warnings.append(f'פוליסה {p.get("id","?")} — src=any ו-dst=any — יש לבדוק')

    if migration_type == 'checkpoint_to_forti':
        nat_count = len(parsed.get('nat_rules', []))
        vpn_count = len(parsed.get('vpn_communities', []))
        if nat_count: info.append(f'נמצאו {nat_count} חוקי NAT')
        if vpn_count: warnings.append(f'{vpn_count} VPN Communities — נדרשת קונפיגורציה ידנית לאחר מיגרציה')

    return jsonify({'success': True,
                    'analysis': {'info': info, 'warnings': warnings,
                                 'errors': errors, 'ready_to_migrate': len(errors) == 0}})


@app.route('/api/convert-config', methods=['POST'])
def convert_config():
    data = request.json or {}
    cfg_id         = data.get('config_id', '')
    migration_type = data.get('migration_type', '')
    target_version = data.get('target_version', '7.4')
    options        = data.get('options', {})

    cfg_path = os.path.join(UPLOAD_FOLDER, f'{cfg_id}.json')
    if not os.path.exists(cfg_path):
        return jsonify({'success': False, 'error': 'Config not found'})
    with open(cfg_path, encoding='utf-8') as f:
        cfg_data = json.load(f)
    parsed = cfg_data.get('parsed', {})

    try:
        if migration_type == 'checkpoint_to_forti':
            converter = CheckpointToFortiConverter(target_version=target_version, options=options)
        elif migration_type == 'forti_to_forti':
            converter = FortiToFortiConverter(target_version=target_version, options=options)
        else:
            return jsonify({'success': False, 'error': 'Unknown migration type'})

        result = converter.convert(parsed)
        out_id   = f'output_{cfg_id}'
        out_path = os.path.join(UPLOAD_FOLDER, f'{out_id}.conf')
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(result['config'])

        return jsonify({'success': True, 'output_id': out_id,
                        'stats': result['stats'], 'warnings': result['warnings'],
                        'config_preview': result['config'][:1200]})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/download-output/<out_id>')
def download_output(out_id):
    # Sanitize
    out_id = out_id.replace('..', '').replace('/', '').replace('\\', '')
    out_path = os.path.join(UPLOAD_FOLDER, f'{out_id}.conf')
    if not os.path.exists(out_path):
        return jsonify({'success': False, 'error': 'Output not found'}), 404
    with open(out_path, encoding='utf-8') as f:
        content = f.read()
    return Response(content, mimetype='text/plain',
                    headers={'Content-Disposition': f'attachment; filename="{out_id}.conf"'})


# ── Helpers ───────────────────────────────────────────────────────────────────
def find_free_port(preferred=5099):
    for port in range(preferred, preferred + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('127.0.0.1', port))
                return port
            except OSError:
                continue
    return preferred


def open_browser(port, delay=1.5):
    def _open():
        time.sleep(delay)
        webbrowser.open(f'http://127.0.0.1:{port}')
    threading.Thread(target=_open, daemon=True).start()


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='FireWall Migrator Pro')
    parser.add_argument('--port', type=int, default=0)
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()

    port = args.port if args.port else find_free_port(5099)

    print('=' * 55)
    print('  🔥  FireWall Migrator Pro  v2.0')
    print('=' * 55)
    print(f'  ► Server: http://127.0.0.1:{port}')
    print(f'  ► Temp:   {UPLOAD_FOLDER}')
    print('  ► Press Ctrl+C to quit')
    print('=' * 55)

    if not args.no_browser:
        open_browser(port, delay=1.2)

    # Suppress Flask startup banner when running as EXE
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.WARNING)

    app.run(host='127.0.0.1', port=port, debug=False, threaded=True)
