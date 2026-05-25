from datetime import datetime
import re

# Model strings for config-version header
MODEL_STRINGS = {
    'FortiGate-40F':  'FGT40F',
    'FortiGate-60F':  'FGT60F',
    'FortiGate-60E':  'FGT60E',
    'FortiGate-80F':  'FGT80F',
    'FortiGate-100F': 'FGT100F',
    'FortiGate-200F': 'FGT200F',
    'FortiGate-VM':   'FGVMK',
    'Same as source': None,
}

# Commands that are TRULY syntax-changed between versions
# Only things that will cause an actual import error
SYNTAX_CHANGES = {
    # source_version → target_version → [(old_pattern, new_pattern)]
    ('6.4', '7.0'): [
        ('set ssl-ssh-profile certificate-inspection', 'set ssl-ssh-profile "certificate-inspection"'),
    ],
    ('6.4', '7.2'): [
        ('set ssl-ssh-profile certificate-inspection', 'set ssl-ssh-profile "certificate-inspection"'),
    ],
    ('6.4', '7.4'): [
        ('set ssl-ssh-profile certificate-inspection', 'set ssl-ssh-profile "certificate-inspection"'),
    ],
    ('7.0', '7.4'): [],
    ('7.2', '7.4'): [],
}

# Things to WARN about (not remove) when migrating between versions
WARNINGS_MAP = {
    ('6.4', '7.0'): [
        'SD-WAN: תחביר השתנה מ-6.4 ל-7.0 — בדוק config system sdwan',
    ],
    ('6.4', '7.2'): [
        'SD-WAN: תחביר השתנה מ-6.4 ל-7.2 — בדוק config system sdwan',
    ],
    ('6.4', '7.4'): [
        'SD-WAN: תחביר השתנה מ-6.4 ל-7.4 — בדוק config system sdwan',
        'FortiGuard DNS filter: שם השתנה ב-7.4 — בדוק dnsfilter-profile',
    ],
    ('7.0', '7.4'): [],
    ('7.2', '7.4'): [],
}


class FortiToFortiConverter:
    def __init__(self, target_version='7.4', target_model='Same as source',
                 source_version=None, options=None):
        self.target_version = target_version
        self.target_model   = target_model
        self.source_version = source_version
        self.options        = options or {}
        self.warnings       = []

    def _detect_source_version(self, raw):
        """Extract version from config-version header line"""
        m = re.search(r'#config-version=\S+-(\d+\.\d+)', raw)
        if m:
            return m.group(1)
        return None

    def _detect_source_model(self, raw):
        """Extract model string from config-version header"""
        m = re.search(r'#config-version=([A-Z0-9]+)-', raw)
        if m:
            return m.group(1)
        return None

    def _update_config_version_line(self, line, source_model, target_model_str):
        """
        Update the #config-version= header line to reflect new model/version.
        Only touches the version header — everything else stays identical.
        """
        if not line.startswith('#config-version='):
            return line

        # Replace version number
        line = re.sub(
            r'(#config-version=\S+?-)(\d+\.\d+\.\d+|\d+\.\d+)',
            lambda m: m.group(1) + self.target_version,
            line
        )

        # Replace model string if user chose a specific target model
        if target_model_str and source_model:
            line = line.replace(source_model, target_model_str)

        return line

    def _apply_syntax_changes(self, line, syntax_rules):
        """Apply known syntax changes between versions"""
        for old, new in syntax_rules:
            if old in line:
                line = line.replace(old, new)
        return line

    def convert(self, parsed):
        raw = parsed.get('raw', '')
        if not raw:
            return {
                'config': '# ERROR: No raw config found',
                'stats': {}, 'warnings': ['לא נמצאה קונפיגורציה גולמית']
            }

        # Detect source info
        src_ver   = self.source_version or self._detect_source_version(raw) or '?'
        src_model = self._detect_source_model(raw)
        tgt_model_str = MODEL_STRINGS.get(self.target_model)  # None = keep same

        # Get syntax rules for this version pair
        ver_key      = (src_ver, self.target_version)
        syntax_rules = SYNTAX_CHANGES.get(ver_key, [])
        warn_list    = WARNINGS_MAP.get(ver_key, [])

        # Build output — line by line, change ONLY what must change
        out_lines = [
            f'# Migrated FortiGate {src_ver} → FortiGate {self.target_version}',
            f'# Source model: {src_model or "unknown"}  →  Target model: {self.target_model}',
            f'# Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
            f'# FireWall Migrator Pro',
            '',
        ]

        syntax_fixes = 0
        for line in raw.splitlines():
            # 1. Update config-version header
            if line.startswith('#config-version='):
                new_line = self._update_config_version_line(line, src_model, tgt_model_str)
                if new_line != line:
                    out_lines.append(new_line)
                    syntax_fixes += 1
                else:
                    out_lines.append(line)
                continue

            # 2. Apply known syntax changes
            new_line = self._apply_syntax_changes(line, syntax_rules)
            if new_line != line:
                syntax_fixes += 1
            out_lines.append(new_line)

        # Build warnings
        self.warnings = list(warn_list)
        if syntax_fixes > 0:
            self.warnings.append(f'תוקנו {syntax_fixes} שורות עם שינויי syntax בין גרסאות')
        if parsed.get('vpn'):
            self.warnings.append('VPN — אמת PSK ו-certificates ידנית לאחר מיגרציה')

        # Stats
        stats = {
            'interfaces_converted': len(parsed.get('interfaces', [])),
            'policies_converted':   len(parsed.get('policies', [])),
            'addresses_converted':  len(parsed.get('objects', {}).get('addresses', [])),
            'services_converted':   len(parsed.get('objects', {}).get('services', [])),
            'routes_converted':     len(parsed.get('routes', [])),
            'vpn_tunnels':          len(parsed.get('vpn', [])),
            'lines_total':          len(out_lines),
            'syntax_fixes':         syntax_fixes,
        }

        return {
            'config':   '\n'.join(out_lines),
            'stats':    stats,
            'warnings': self.warnings,
        }
