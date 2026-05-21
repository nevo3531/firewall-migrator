from datetime import datetime

DEPRECATED = {
    '7.4': ['set device-identification enable', 'set scan-botnet-connections block',
            'set av-profile', 'set webcache enable'],
    '7.2': ['set webcache enable'],
    '7.0': [], '6.4': [],
}


class FortiToFortiConverter:
    def __init__(self, target_version='7.4', options=None):
        self.target_version = target_version
        self.options = options or {}
        self.warnings = []

    def convert(self, parsed):
        raw = parsed.get('raw', '')
        depr = DEPRECATED.get(self.target_version, [])
        out_lines, removed = [], 0

        out_lines += [
            f'# Migrated FortiGate → FortiGate {self.target_version}',
            f'# Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
            f'# FireWall Migrator Pro', ''
        ]

        if raw:
            for line in raw.splitlines():
                s = line.strip()
                skip = any(d in s for d in depr)
                if skip:
                    out_lines.append(f'    # [REMOVED — deprecated in {self.target_version}]: {s}')
                    removed += 1
                else:
                    out_lines.append(line)
        else:
            out_lines.append('# (no raw config — reconstruct from parsed data)')

        if removed:
            self.warnings.append(f'הוסרו {removed} שורות deprecated לגרסה {self.target_version}')
        if parsed.get('vpn'):
            self.warnings.append('VPN tunnels — אמת PSK וcertificates ידנית לאחר מיגרציה')

        stats = {
            'interfaces_converted': len(parsed.get('interfaces', [])),
            'policies_converted': len(parsed.get('policies', [])),
            'addresses_converted': len(parsed.get('objects', {}).get('addresses', [])),
            'services_converted': len(parsed.get('objects', {}).get('services', [])),
            'routes_converted': len(parsed.get('routes', [])),
            'vpn_tunnels': len(parsed.get('vpn', [])),
        }
        return {'config': '\n'.join(out_lines), 'stats': stats, 'warnings': self.warnings}
