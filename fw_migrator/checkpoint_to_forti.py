from datetime import datetime


class CheckpointToFortiConverter:
    def __init__(self, target_version='7.4', options=None):
        self.target_version = target_version
        self.options = options or {}
        self.warnings = []

    def convert(self, parsed):
        out = [
            f'# Converted from CheckPoint → FortiGate {self.target_version}',
            f'# Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
            f'# FireWall Migrator Pro', '',
        ]
        out += self._interfaces(parsed)
        out += self._addresses(parsed)
        out += self._addr_groups(parsed)
        out += self._services(parsed)
        out += self._policies(parsed)
        out += self._routes(parsed)
        stats = {
            'interfaces_converted': len(parsed.get('interfaces', [])),
            'policies_converted': len(parsed.get('policies', [])),
            'addresses_converted': len(parsed.get('objects', {}).get('addresses', [])),
            'services_converted': len(parsed.get('objects', {}).get('services', [])),
            'routes_converted': len(parsed.get('routes', [])),
            'vpn_tunnels': 0,
        }
        return {'config': '\n'.join(out), 'stats': stats, 'warnings': self.warnings}

    def _safe(self, n):
        return str(n)[:63].replace(' ', '_').replace('/', '_').replace('\\', '_') if n else 'unknown'

    def _mask(self, prefix):
        try:
            p = int(prefix); m = (0xFFFFFFFF << (32 - p)) & 0xFFFFFFFF
            return f'{(m>>24)&0xFF}.{(m>>16)&0xFF}.{(m>>8)&0xFF}.{m&0xFF}'
        except: return '255.255.255.0'

    def _interfaces(self, parsed):
        ifaces = parsed.get('interfaces', [])
        if not ifaces: return []
        out = ['config system interface']
        for i in ifaces:
            mask = self._mask(i.get('mask_length', '24'))
            out += [f'    edit "{self._safe(i.get("name"))}"',
                    '        set mode static',
                    f'        set ip {i.get("ip","0.0.0.0")} {mask}',
                    '        set allowaccess ping https ssh',
                    '    next']
        return out + ['end', '']

    def _addresses(self, parsed):
        addrs = parsed.get('objects', {}).get('addresses', [])
        if not addrs: return []
        out = ['config firewall address']
        for a in addrs:
            out += [f'    edit "{self._safe(a.get("name"))}"',
                    '        set type ipmask',
                    f'        set subnet {a.get("subnet","0.0.0.0")} {a.get("subnet_mask","255.255.255.255")}',
                    '    next']
        return out + ['end', '']

    def _addr_groups(self, parsed):
        groups = parsed.get('objects', {}).get('address_groups', [])
        if not groups: return []
        out = ['config firewall addrgrp']
        for g in groups:
            members = ' '.join(f'"{self._safe(m)}"' for m in g.get('members', [])[:20])
            out += [f'    edit "{self._safe(g.get("name"))}"',
                    f'        set member {members}' if members else '        set member "all"',
                    '    next']
        return out + ['end', '']

    def _services(self, parsed):
        svcs = parsed.get('objects', {}).get('services', [])
        if not svcs: return []
        out = ['config firewall service custom']
        for s in svcs:
            proto = s.get('protocol', 'TCP').upper()
            port = s.get('tcp_portrange') or s.get('udp_portrange', '0')
            out += [f'    edit "{self._safe(s.get("name"))}"',
                    '        set protocol TCP/UDP/SCTP',
                    f'        set {"tcp" if proto=="TCP" else "udp"}-portrange {port}',
                    '    next']
        return out + ['end', '']

    def _policies(self, parsed):
        policies = parsed.get('policies', [])
        if not policies: return []
        out = ['config firewall policy']
        for i, p in enumerate(policies, 1):
            src = self._safe(p.get('src', 'any')); src = 'all' if src == 'any' else src
            dst = self._safe(p.get('dst', 'any')); dst = 'all' if dst == 'any' else dst
            action = 'accept' if 'accept' in p.get('action', 'accept').lower() else 'deny'
            out += [f'    edit {i}',
                    '        set srcintf "any"', '        set dstintf "any"',
                    f'        set srcaddr "{src}"', f'        set dstaddr "{dst}"',
                    f'        set action {action}', '        set schedule "always"',
                    '        set service "ALL"', '        set logtraffic all',
                    '    next']
        if any('any' in str(p.get('src','')) or 'any' in str(p.get('dst','')) for p in policies):
            self.warnings.append('חלק מהפוליסות כוללות any — בדוק לאחר מיגרציה')
        return out + ['end', '']

    def _routes(self, parsed):
        routes = parsed.get('routes', [])
        if not routes: return []
        out = ['config router static']
        for i, r in enumerate(routes, 1):
            mask = self._mask(r.get('prefix', '24'))
            out += [f'    edit {i}',
                    f'        set dst {r.get("dst","0.0.0.0")} {mask}',
                    f'        set gateway {r.get("gateway","0.0.0.0")}',
                    '    next']
        return out + ['end', '']
