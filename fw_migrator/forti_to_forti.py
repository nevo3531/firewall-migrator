"""
FortiGate → FortiGate Migration Converter
Supports all models and all FortiOS versions.

Philosophy:
- Touch ONLY the header lines (#config-version, #buildno)
- Never delete or modify any policy, object, interface, or setting
- Warn about known syntax changes but do NOT auto-fix unless 100% safe
"""
from datetime import datetime
import re

# ── Build numbers per FortiOS major.minor version ────────────────────────────
# These are the latest known stable builds for each version
VERSION_BUILDS = {
    '6.0': '6457',
    '6.2': '1378',
    '6.4': '2093',
    '7.0': '0489',
    '7.2': '1639',
    '7.4': '2662',
    '7.6': '3401',
}

# ── Model string mapping ──────────────────────────────────────────────────────
MODEL_STRINGS = {
    'FortiGate-30E':  'FGT30E',
    'FortiGate-40F':  'FGT40F',
    'FortiGate-60D':  'FGT60D',
    'FortiGate-60E':  'FGT60E',
    'FortiGate-60F':  'FGT60F',
    'FortiGate-70F':  'FGT70F',
    'FortiGate-80E':  'FGT80E',
    'FortiGate-80F':  'FGT80F',
    'FortiGate-100E': 'FGT100E',
    'FortiGate-100F': 'FGT100F',
    'FortiGate-200E': 'FGT200E',
    'FortiGate-200F': 'FGT200F',
    'FortiGate-300E': 'FGT300E',
    'FortiGate-400E': 'FGT400E',
    'FortiGate-600E': 'FGT600E',
    'FortiGate-VM':   'FGVMK',
    'Same as source': None,
}

# ── Only TRUE breaking syntax changes (cause import errors) ──────────────────
# Format: (src_ver, dst_ver) -> list of (old_string, new_string)
# Keep this list MINIMAL — only add things that WILL break on import
SYNTAX_FIXES = {
    ('6.0', '7.0'): [
        ('set ssl-ssh-profile certificate-inspection', 'set ssl-ssh-profile "certificate-inspection"'),
    ],
    ('6.0', '7.2'): [
        ('set ssl-ssh-profile certificate-inspection', 'set ssl-ssh-profile "certificate-inspection"'),
    ],
    ('6.0', '7.4'): [
        ('set ssl-ssh-profile certificate-inspection', 'set ssl-ssh-profile "certificate-inspection"'),
    ],
    ('6.0', '7.6'): [
        ('set ssl-ssh-profile certificate-inspection', 'set ssl-ssh-profile "certificate-inspection"'),
    ],
    ('6.2', '7.0'): [
        ('set ssl-ssh-profile certificate-inspection', 'set ssl-ssh-profile "certificate-inspection"'),
    ],
    ('6.2', '7.2'): [
        ('set ssl-ssh-profile certificate-inspection', 'set ssl-ssh-profile "certificate-inspection"'),
    ],
    ('6.2', '7.4'): [
        ('set ssl-ssh-profile certificate-inspection', 'set ssl-ssh-profile "certificate-inspection"'),
    ],
    ('6.2', '7.6'): [
        ('set ssl-ssh-profile certificate-inspection', 'set ssl-ssh-profile "certificate-inspection"'),
    ],
    ('6.4', '7.0'): [
        ('set ssl-ssh-profile certificate-inspection', 'set ssl-ssh-profile "certificate-inspection"'),
    ],
    ('6.4', '7.2'): [
        ('set ssl-ssh-profile certificate-inspection', 'set ssl-ssh-profile "certificate-inspection"'),
    ],
    ('6.4', '7.4'): [
        ('set ssl-ssh-profile certificate-inspection', 'set ssl-ssh-profile "certificate-inspection"'),
    ],
    ('6.4', '7.6'): [
        ('set ssl-ssh-profile certificate-inspection', 'set ssl-ssh-profile "certificate-inspection"'),
    ],
}

# ── Informational warnings only (no auto-fix) ────────────────────────────────
WARNINGS = {
    ('6.0', '7.0'): ['SD-WAN syntax שינה מ-6.x ל-7.x — בדוק config system sdwan'],
    ('6.0', '7.2'): ['SD-WAN syntax שינה מ-6.x ל-7.x — בדוק config system sdwan'],
    ('6.0', '7.4'): ['SD-WAN syntax שינה מ-6.x ל-7.x — בדוק config system sdwan'],
    ('6.0', '7.6'): ['SD-WAN syntax שינה מ-6.x ל-7.x — בדוק config system sdwan'],
    ('6.2', '7.0'): ['SD-WAN syntax שינה מ-6.x ל-7.x — בדוק config system sdwan'],
    ('6.2', '7.2'): ['SD-WAN syntax שינה מ-6.x ל-7.x — בדוק config system sdwan'],
    ('6.2', '7.4'): ['SD-WAN syntax שינה מ-6.x ל-7.x — בדוק config system sdwan'],
    ('6.2', '7.6'): ['SD-WAN syntax שינה מ-6.x ל-7.x — בדוק config system sdwan'],
    ('6.4', '7.0'): ['SD-WAN syntax שינה מ-6.x ל-7.x — בדוק config system sdwan'],
    ('6.4', '7.2'): ['SD-WAN syntax שינה מ-6.x ל-7.x — בדוק config system sdwan'],
    ('6.4', '7.4'): ['SD-WAN syntax שינה מ-6.x ל-7.x — בדוק config system sdwan'],
    ('6.4', '7.6'): ['SD-WAN syntax שינה מ-6.x ל-7.x — בדוק config system sdwan'],
}


class FortiToFortiConverter:
    def __init__(self, target_version='7.4', target_model='Same as source',
                 source_version=None, options=None):
        self.target_version = target_version
        self.target_model   = target_model
        self.source_version = source_version
        self.options        = options or {}
        self.warnings       = []

    # ── Detection ─────────────────────────────────────────────────────────────
    def _parse_version_line(self, raw):
        """
        Parse #config-version line.
        Returns (model_str, full_version, major_minor, build, date, rest) or None
        """
        m = re.match(
            r'#config-version=([A-Z0-9]+)-(\d+\.\d+)\.(\d+)-FW-build(\d+)-(\d+):(.*)',
            raw
        )
        if m:
            model    = m.group(1)
            major    = m.group(2)   # e.g. "6.4"
            minor    = m.group(3)   # e.g. "14"
            build    = m.group(4)
            date     = m.group(5)
            rest     = m.group(6)
            return model, f'{major}.{minor}', major, build, date, rest
        return None

    def _detect_source_version(self, raw):
        for line in raw.splitlines()[:10]:
            parsed = self._parse_version_line(line)
            if parsed:
                return parsed[2]  # major_minor e.g. "6.4"
        return None

    def _detect_source_model(self, raw):
        for line in raw.splitlines()[:10]:
            parsed = self._parse_version_line(line)
            if parsed:
                return parsed[0]
        return None

    # ── Header update ─────────────────────────────────────────────────────────
    def _rewrite_version_line(self, line, src_model, tgt_model_str, tgt_ver, tgt_build):
        parsed = self._parse_version_line(line)
        if not parsed:
            return line  # Can't parse — leave untouched

        model, full_ver, major, build, date, rest = parsed

        # Choose target model string
        new_model = tgt_model_str if tgt_model_str else model

        # Keep minor version from source (e.g. 6.4.14 → keep .14 style)
        # but update the major.minor part
        new_line = (
            f'#config-version={new_model}-{tgt_ver}.{minor_from_full(full_ver)}'
            f'-FW-build{tgt_build}-{date}:{rest}'
        )
        return new_line

    # ── Main convert ──────────────────────────────────────────────────────────
    def convert(self, parsed):
        raw = parsed.get('raw', '')
        if not raw:
            return {'config': '# ERROR: No raw config', 'stats': {}, 'warnings': ['לא נמצאה קונפיגורציה']}

        # Detect source info
        src_ver   = self.source_version or self._detect_source_version(raw) or '6.4'
        src_model = self._detect_source_model(raw)
        tgt_model_str = MODEL_STRINGS.get(self.target_model)
        tgt_build     = VERSION_BUILDS.get(self.target_version, '0000')

        ver_key      = (src_ver, self.target_version)
        syntax_rules = SYNTAX_FIXES.get(ver_key, [])
        warn_list    = list(WARNINGS.get(ver_key, []))

        fixes   = 0
        out_lines = []

        for line in raw.splitlines():
            # ── Line 1: config-version header ──
            if line.startswith('#config-version='):
                pv = self._parse_version_line(line)
                if pv:
                    model, full_ver, major, build, date, rest = pv
                    new_model = tgt_model_str if tgt_model_str else model
                    minor     = full_ver.split('.')[-1] if '.' in full_ver else '0'
                    new_line  = (
                        f'#config-version={new_model}-{self.target_version}.{minor}'
                        f'-FW-build{tgt_build}-{date}:{rest}'
                    )
                    if new_line != line:
                        fixes += 1
                    out_lines.append(new_line)
                else:
                    out_lines.append(line)
                continue

            # ── Line 2: buildno header ──
            if line.startswith('#buildno='):
                new_line = f'#buildno={tgt_build}'
                if new_line != line:
                    fixes += 1
                out_lines.append(new_line)
                continue

            # ── All other lines: apply syntax fixes only if needed ──
            new_line = line
            for old, new in syntax_rules:
                if old in new_line:
                    new_line = new_line.replace(old, new)
                    fixes += 1
            out_lines.append(new_line)

        # Warnings
        self.warnings = warn_list
        if fixes:
            self.warnings.append(f'עודכנו {fixes} שורות (header + syntax)')
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
            'syntax_fixes':         fixes,
        }

        return {'config': '\n'.join(out_lines), 'stats': stats, 'warnings': self.warnings}


def minor_from_full(full_ver):
    """Extract minor version number: '6.4.14' → '14', '7.4' → '0'"""
    parts = full_ver.split('.')
    return parts[-1] if len(parts) > 2 else '0'
