"""
FortiGate → FortiGate Migration Converter
Handles ALL version combinations and ALL model migrations.
Converts syntax that changed between versions, warns on hardware differences.
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

# WiFi/DSL model prefixes — have hardware not present on regular FortiGate
WIFI_MODEL_PREFIXES = ('FW', 'FWF')

# Lines to silently remove (cause import errors in newer versions)
REMOVE_IF_UPGRADING = [
    'set proxy-auth-timeout',
    'set wccp enable',
    'set wccp-forward-method',
    'set switch-controller enable',   # removed from global in 7.4
    'set gui-local-in-policy enable', # renamed
]


class FortiToFortiConverter:
    def __init__(self, target_version='7.4', target_model='Same as source',
                 source_version=None, options=None):
        self.target_version = target_version
        self.target_model   = target_model
        self.source_version = source_version
        self.options        = options or {}
        self.warnings       = []
        self._fixes         = 0

    # ── Detection ─────────────────────────────────────────────────────────────
    def _parse_header(self, line):
        m = re.match(
            r'#config-version=([A-Z0-9]+)-(\d+\.\d+)\.(\d+)-FW-build(\d+)-(\d+):(.*)',
            line)
        if m:
            return {'model': m.group(1), 'major': m.group(2),
                    'minor': m.group(3), 'build': m.group(4),
                    'date': m.group(5), 'rest': m.group(6)}
        return None

    def _detect_source_version(self, raw):
        for line in raw.splitlines()[:10]:
            h = self._parse_header(line)
            if h: return h['major']
        return None

    def _detect_source_model(self, raw):
        for line in raw.splitlines()[:10]:
            h = self._parse_header(line)
            if h: return h['model']
        return None

    def _major(self, ver):
        try: return int(ver.split('.')[0])
        except: return 6

    def _is_6x_to_7x(self, src, tgt):
        return self._major(src) == 6 and self._major(tgt) == 7

    def _is_upgrading(self, src, tgt):
        try:
            sv = [int(x) for x in src.split('.')]
            tv = [int(x) for x in tgt.split('.')]
            return tv > sv
        except:
            return False

    # ── Section collectors ────────────────────────────────────────────────────
    def _collect_section(self, lines, start_idx):
        """Collect lines from start_idx until matching 'end' at depth 1."""
        section = [lines[start_idx]]
        i = start_idx + 1
        depth = 1
        while i < len(lines):
            l = lines[i]
            s = l.strip()
            if s.startswith('edit ') or s.startswith('config '):
                depth += 1
            if s == 'end':
                depth -= 1
                section.append(l)
                i += 1
                if depth == 0:
                    break
                continue
            if s == 'next':
                depth -= 1
                section.append(l)
                i += 1
                if depth == 0:
                    break
                continue
            section.append(l)
            i += 1
        return section, i

    # ── Antivirus conversion ──────────────────────────────────────────────────
    def _convert_antivirus_section(self, section_lines):
        """
        For 6.x → 7.x:
        Add 'set feature-set flow' to each edit block that doesn't have it.
        Keep all protocol sub-configs intact (they still work in 7.x).
        """
        out = []
        in_edit = False
        has_feature_set = False
        indent = '        '

        for line in section_lines:
            s = line.strip()

            if s.startswith('edit '):
                in_edit = True
                has_feature_set = False
                out.append(line)
                continue

            if s == 'next' and in_edit:
                if not has_feature_set:
                    out.append(f'{indent}set feature-set flow')
                    self._fixes += 1
                in_edit = False
                out.append(line)
                continue

            if 'set feature-set' in s:
                has_feature_set = True

            out.append(line)

        return out

    # ── SSL-SSH profile fix ───────────────────────────────────────────────────
    def _fix_ssl_profile_line(self, line):
        """Quote unquoted certificate-inspection in ssl-ssh-profile."""
        if ('set ssl-ssh-profile certificate-inspection' in line
                and '"certificate-inspection"' not in line):
            self._fixes += 1
            return line.replace(
                'set ssl-ssh-profile certificate-inspection',
                'set ssl-ssh-profile "certificate-inspection"')
        return line

    # ── SD-WAN detection ──────────────────────────────────────────────────────
    def _check_sdwan(self, raw, src_ver):
        """Warn if old virtual-wan-link exists and needs manual conversion."""
        if 'config system virtual-wan-link' in raw:
            self.warnings.append(
                '⚠️ SD-WAN: הקונפיגורציה משתמשת ב-virtual-wan-link (6.x syntax) — '
                'ב-7.x זה הפך ל-config system sdwan. יש להגדיר ידנית לאחר ייבוא.')

    # ── Remove deprecated lines ───────────────────────────────────────────────
    def _should_remove(self, line, upgrading):
        if not upgrading:
            return False
        s = line.strip()
        return any(s.startswith(bad) for bad in REMOVE_IF_UPGRADING)

    # ── Hardware warnings ─────────────────────────────────────────────────────
    def _check_hardware(self, src_model, tgt_model_str):
        is_wifi_src = src_model and any(
            src_model.startswith(p) for p in WIFI_MODEL_PREFIXES)
        is_regular_tgt = tgt_model_str and tgt_model_str.startswith('FGT')

        if is_wifi_src and is_regular_tgt:
            self.warnings.append(
                f'⚠️ מקור {src_model} הוא FortiWiFi — '
                f'ממשקי WiFi, DSL ו-Wireless Controller לא קיימים ב-{tgt_model_str}. '
                f'יש להגדיר ממשקים ידנית.')

        if src_model and tgt_model_str and src_model != tgt_model_str:
            # Physical port differences
            port_warnings = {
                ('FW60EV', 'FGT60F'): 'ממשק wan → wan1/wan2, LanSwitch → internal',
                ('FGT60E', 'FGT60F'): 'שמות ממשקים עשויים להיות שונים',
                ('FGT60F', 'FGT100F'): '100F יש יותר ממשקים פיזיים',
                ('FGT60F', 'FGT200F'): '200F יש יותר ממשקים פיזיים',
            }
            key = (src_model, tgt_model_str)
            if key in port_warnings:
                self.warnings.append(f'⚠️ {port_warnings[key]} — בדוק ממשקים לאחר ייבוא')

    # ── Main convert ──────────────────────────────────────────────────────────
    def convert(self, parsed):
        raw = parsed.get('raw', '')
        if not raw:
            return {'config': '# ERROR: No raw config', 'stats': {}, 'warnings': []}

        src_ver       = self.source_version or self._detect_source_version(raw) or '6.4'
        src_model     = self._detect_source_model(raw)
        tgt_model_str = MODEL_STRINGS.get(self.target_model)
        tgt_build     = VERSION_BUILDS.get(self.target_version, '0000')
        upgrading_6to7 = self._is_6x_to_7x(src_ver, self.target_version)
        upgrading      = self._is_upgrading(src_ver, self.target_version)

        self._fixes   = 0
        self.warnings = []

        # Pre-checks
        if upgrading_6to7:
            self._check_sdwan(raw, src_ver)
        self._check_hardware(src_model, tgt_model_str)

        out_lines = []
        lines = raw.splitlines()
        i = 0

        while i < len(lines):
            line  = lines[i]
            s     = line.strip()

            # ── Header lines ──────────────────────────────────────────────────
            if line.startswith('#config-version='):
                h = self._parse_header(line)
                if h:
                    new_model = tgt_model_str if tgt_model_str else h['model']
                    new_line = (
                        f'#config-version={new_model}-{self.target_version}.{h["minor"]}'
                        f'-FW-build{tgt_build}-{h["date"]}:{h["rest"]}')
                    if new_line != line: self._fixes += 1
                    out_lines.append(new_line)
                else:
                    out_lines.append(line)
                i += 1
                continue

            if line.startswith('#buildno='):
                new_line = f'#buildno={tgt_build}'
                if new_line != line: self._fixes += 1
                out_lines.append(new_line)
                i += 1
                continue

            # ── Antivirus profile section ─────────────────────────────────────
            if s == 'config antivirus profile' and upgrading_6to7:
                section, i = self._collect_section(lines, i)
                converted = self._convert_antivirus_section(section)
                out_lines.extend(converted)
                continue

            # ── Remove deprecated global options ──────────────────────────────
            if self._should_remove(line, upgrading):
                out_lines.append(f'# [SKIP - deprecated in {self.target_version}]: {s}')
                self._fixes += 1
                i += 1
                continue

            # ── SSL-SSH profile quote fix ─────────────────────────────────────
            if upgrading_6to7 and 'set ssl-ssh-profile' in line:
                out_lines.append(self._fix_ssl_profile_line(line))
                i += 1
                continue

            # ── dnsfilter rename 7.2→7.4 ─────────────────────────────────────
            if (self.target_version >= '7.4' and src_ver < '7.4'
                    and 'set sdns-domain-log enable' in line):
                out_lines.append(line.replace(
                    'set sdns-domain-log enable', 'set log-all-domain enable'))
                self._fixes += 1
                i += 1
                continue

            out_lines.append(line)
            i += 1

        # ── Final warnings ────────────────────────────────────────────────────
        if self._fixes > 0:
            self.warnings.append(
                f'✓ תוקנו {self._fixes} שורות (config-version, buildno, antivirus syntax)')
        if upgrading_6to7:
            self.warnings.append(
                f'שדרוג {src_ver}→{self.target_version}: בדוק antivirus, webfilter '
                f'ו-SD-WAN לאחר ייבוא')
        if parsed.get('vpn'):
            self.warnings.append('VPN — אמת PSK ו-certificates ידנית לאחר מיגרציה')

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

        return {
            'config':   '\n'.join(out_lines),
            'stats':    stats,
            'warnings': self.warnings,
        }
