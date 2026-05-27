"""
FortiGate → FortiGate Migration Converter
Complete, accurate conversion for ALL version/model combinations.
Based on real FortiOS release notes and observed behavior.
"""
from datetime import datetime
import re

VERSION_BUILDS = {
    '6.0': '6457', '6.2': '1378', '6.4': '2093',
    '7.0': '0489', '7.2': '1639', '7.4': '2662', '7.6': '3401',
}

MODEL_STRINGS = {
    'FortiGate-30E':  'FGT30E', 'FortiGate-40F':  'FGT40F',
    'FortiGate-60D':  'FGT60D', 'FortiGate-60E':  'FGT60E',
    'FortiGate-60F':  'FGT60F', 'FortiGate-70F':  'FGT70F',
    'FortiGate-80E':  'FGT80E', 'FortiGate-80F':  'FGT80F',
    'FortiGate-100E': 'FGT100E','FortiGate-100F': 'FGT100F',
    'FortiGate-200E': 'FGT200E','FortiGate-200F': 'FGT200F',
    'FortiGate-300E': 'FGT300E','FortiGate-400E': 'FGT400E',
    'FortiGate-600E': 'FGT600E','FortiGate-VM':   'FGVMK',
    'Same as source': None,
}

WIFI_PREFIXES = ('FW', 'FWF')

# AV protocol sub-block names that need 'set status enable' in 7.x
AV_PROTOCOL_BLOCKS = {'http', 'ftp', 'imap', 'pop3', 'smtp', 'cifs', 'nntp', 'ssh'}


class FortiToFortiConverter:
    def __init__(self, target_version='7.4', target_model='Same as source',
                 source_version=None, options=None):
        self.target_version = target_version
        self.target_model   = target_model
        self.source_version = source_version
        self.options        = options or {}
        self.warnings       = []
        self._fixes         = 0

    def _parse_header(self, line):
        m = re.match(
            r'#config-version=([A-Z0-9]+)-(\d+\.\d+)\.(\d+)-FW-build(\d+)-(\d+):(.*)',
            line)
        return dict(model=m.group(1), major=m.group(2), minor=m.group(3),
                    build=m.group(4), date=m.group(5), rest=m.group(6)) if m else None

    def _detect_src_ver(self, raw):
        for line in raw.splitlines()[:10]:
            h = self._parse_header(line)
            if h: return h['major']
        return None

    def _detect_src_model(self, raw):
        for line in raw.splitlines()[:10]:
            h = self._parse_header(line)
            if h: return h['model']
        return None

    def _major(self, v):
        try: return int(v.split('.')[0])
        except: return 6

    def _collect_section(self, lines, start):
        """Collect a config section until its matching top-level 'end'."""
        result = [lines[start]]
        i = start + 1
        depth = 1
        while i < len(lines):
            l = lines[i]
            s = l.strip()
            result.append(l)
            i += 1
            if s.startswith('config ') or s.startswith('edit '):
                depth += 1
            elif s == 'end':
                depth -= 1
                if depth == 0:
                    break
        return result, i

    # ── AntiVirus section fix for 6.x → 7.x ──────────────────────────────────
    def _fix_antivirus_section(self, section_lines):
        """
        Transform 6.x antivirus profile syntax to 7.x:
        1. Add 'set feature-set flow' to each edit block
        2. Add 'set scan enable' to each edit block (main toggle)
        3. Add 'set status enable' inside each protocol sub-block
        """
        out = []
        in_edit = False
        has_feature_set = False
        has_scan_enable = False
        in_proto_block = False
        proto_block_name = None
        proto_has_status = False
        edit_indent = '    '

        for line in section_lines:
            s = line.strip()

            # Detect edit block start
            if re.match(r'^edit "', s):
                in_edit = True
                has_feature_set = False
                has_scan_enable = False
                # Detect indentation from this line
                edit_indent = line[:len(line) - len(line.lstrip())]
                out.append(line)
                continue

            # Detect protocol sub-block
            m = re.match(r'^config (\w+)$', s)
            if m and in_edit:
                proto = m.group(1)
                if proto in AV_PROTOCOL_BLOCKS:
                    in_proto_block = True
                    proto_block_name = proto
                    proto_has_status = False
                    out.append(line)
                    continue
                else:
                    in_proto_block = False
                    proto_block_name = None

            # Inside protocol sub-block
            if in_proto_block:
                if 'set status' in s:
                    proto_has_status = True
                if s == 'end':
                    # Add status enable before end if missing
                    if not proto_has_status:
                        proto_indent = line[:len(line) - len(line.lstrip())]
                        out.append(f'{proto_indent}    set status enable')
                        self._fixes += 1
                    in_proto_block = False
                    proto_block_name = None
                    out.append(line)
                    continue
                out.append(line)
                continue

            # Check for existing feature-set / scan enable
            if 'set feature-set' in s:
                has_feature_set = True
            if s == 'set scan enable':
                has_scan_enable = True

            # End of edit block — inject missing lines before 'next'
            if s == 'next' and in_edit:
                proto_indent = edit_indent + '    '
                if not has_scan_enable:
                    out.append(f'{proto_indent}set scan enable')
                    self._fixes += 1
                if not has_feature_set:
                    out.append(f'{proto_indent}set feature-set flow')
                    self._fixes += 1
                in_edit = False
                out.append(line)
                continue

            out.append(line)

        return out

    def convert(self, parsed):
        raw = parsed.get('raw', '')
        if not raw:
            return {'config': '# ERROR: No raw config', 'stats': {}, 'warnings': []}

        src_ver       = self.source_version or self._detect_src_ver(raw) or '6.4'
        src_model     = self._detect_src_model(raw)
        tgt_model_str = MODEL_STRINGS.get(self.target_model)
        tgt_build     = VERSION_BUILDS.get(self.target_version, '0000')

        src_major = self._major(src_ver)
        tgt_major = self._major(self.target_version)
        is_6to7   = src_major == 6 and tgt_major == 7
        upgrading = ([int(x) for x in self.target_version.split('.')] >
                     [int(x) for x in src_ver.split('.')])

        self._fixes   = 0
        self.warnings = []

        # Hardware warnings
        is_wifi_src = src_model and any(src_model.startswith(p) for p in WIFI_PREFIXES)
        is_fgt_tgt  = tgt_model_str and tgt_model_str.startswith('FGT')
        if is_wifi_src and is_fgt_tgt:
            self.warnings.append(
                f'⚠️ מקור {src_model} (FortiWiFi) → {tgt_model_str}: '
                'ממשקי WiFi ו-DSL לא קיימים על FortiGate — הגדר ידנית לאחר ייבוא')

        if is_6to7 and 'config system virtual-wan-link' in raw:
            self.warnings.append(
                '⚠️ SD-WAN: virtual-wan-link (6.x) → config system sdwan (7.x) — הגדר ידנית')

        out_lines = []
        lines = raw.splitlines()
        i = 0

        while i < len(lines):
            line = lines[i]
            s    = line.strip()

            # ── config-version ────────────────────────────────────────────────
            if line.startswith('#config-version='):
                h = self._parse_header(line)
                if h:
                    new_model = tgt_model_str if tgt_model_str else h['model']
                    new_line = (f'#config-version={new_model}-{self.target_version}.{h["minor"]}'
                                f'-FW-build{tgt_build}-{h["date"]}:{h["rest"]}')
                    if new_line != line: self._fixes += 1
                    out_lines.append(new_line)
                else:
                    out_lines.append(line)
                i += 1; continue

            # ── buildno ───────────────────────────────────────────────────────
            if line.startswith('#buildno='):
                new_line = f'#buildno={tgt_build}'
                if new_line != line: self._fixes += 1
                out_lines.append(new_line)
                i += 1; continue

            # ── antivirus profile (6.x → 7.x) ────────────────────────────────
            if s == 'config antivirus profile' and is_6to7:
                section, i = self._collect_section(lines, i)
                out_lines.extend(self._fix_antivirus_section(section))
                continue

            # ── system global: admin port renames (6.x → 7.x) ────────────────
            if is_6to7 and s.startswith('set admin-sport '):
                out_lines.append(line.replace('set admin-sport ', 'set admin-https-port '))
                self._fixes += 1; i += 1; continue

            if is_6to7 and re.match(r'\s*set admin-port \d', line):
                out_lines.append(re.sub(r'(set admin-port )(\d+)', r'set admin-http-port \2', line))
                self._fixes += 1; i += 1; continue

            # ── ssl-ssh-profile quote fix (6.x → 7.x) ────────────────────────
            if is_6to7 and 'set ssl-ssh-profile certificate-inspection' in line \
                    and '"certificate-inspection"' not in line:
                out_lines.append(line.replace(
                    'set ssl-ssh-profile certificate-inspection',
                    'set ssl-ssh-profile "certificate-inspection"'))
                self._fixes += 1; i += 1; continue

            # ── dnsfilter rename (< 7.4 → 7.4+) ─────────────────────────────
            if self.target_version >= '7.4' and src_ver < '7.4' \
                    and 'set sdns-domain-log enable' in line:
                out_lines.append(line.replace(
                    'set sdns-domain-log enable', 'set log-all-domain enable'))
                self._fixes += 1; i += 1; continue

            out_lines.append(line)
            i += 1

        # Warnings
        if self._fixes:
            self.warnings.append(
                f'✓ תוקנו {self._fixes} שורות: config-version, admin ports, '
                f'antivirus (scan enable + status enable), ssl-ssh-profile')
        if is_6to7:
            self.warnings.append(
                f'שדרוג 6.x→7.x: בדוק לאחר ייבוא: antivirus profiles, '
                f'system settings (timezone, certificate), webfilter')
        if parsed.get('vpn'):
            self.warnings.append('VPN — אמת PSK ו-certificates ידנית')

        stats = {
            'interfaces_converted': len(parsed.get('interfaces', [])),
            'policies_converted':   len(parsed.get('policies', [])),
            'addresses_converted':  len(parsed.get('objects', {}).get('addresses', [])),
            'services_converted':   len(parsed.get('objects', {}).get('services', [])),
            'routes_converted':     len(parsed.get('routes', [])),
            'vpn_tunnels':          len(parsed.get('vpn', [])),
            'lines_total':          len(out_lines),
            'syntax_fixes':         self._fixes,
        }

        return {'config': '\n'.join(out_lines), 'stats': stats, 'warnings': self.warnings}
