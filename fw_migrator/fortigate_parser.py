import re


class FortiGateParser:
    def parse(self, raw):
        result = {
            'interfaces': [], 'policies': [], 'routes': [], 'vpn': [],
            'objects': {'addresses': [], 'address_groups': [], 'services': [], 'service_groups': []},
            'raw': raw
        }
        if not raw or not isinstance(raw, str):
            return result
        lines = raw.splitlines()
        self._parse_section(lines, 'config system interface',        result['interfaces'],              self._iface_field)
        self._parse_section(lines, 'config firewall policy',         result['policies'],                self._policy_field)
        self._parse_section(lines, 'config firewall address',        result['objects']['addresses'],    self._addr_field)
        self._parse_section(lines, 'config firewall addrgrp',        result['objects']['address_groups'], self._grp_field)
        self._parse_section(lines, 'config firewall service custom', result['objects']['services'],     self._svc_field)
        self._parse_section(lines, 'config router static',           result['routes'],                  self._route_field)
        self._parse_section(lines, 'config vpn ipsec phase1-interface', result['vpn'],                 self._vpn_field)
        return result

    def _parse_section(self, lines, header, out_list, field_fn):
        in_sec, depth, current = False, 0, {}
        for line in lines:
            s = line.strip()
            if s == header:
                in_sec, depth = True, 1; continue
            if not in_sec: continue
            if s.startswith('edit ') and depth == 1:
                current = {'name': s[5:].strip().strip('"')}; depth = 2
            elif s in ('next', 'end') and depth == 2:
                if current: out_list.append(current)
                current = {}; depth = 1 if s == 'next' else 0
                if s == 'end': in_sec = False
            elif s == 'end' and depth == 1:
                in_sec = False
            elif depth == 2:
                m = re.match(r'set (\S+)\s+(.*)', s)
                if m: field_fn(current, m.group(1), m.group(2).strip().strip('"'))

    def _iface_field(self, d, k, v): d[k] = v
    def _policy_field(self, d, k, v): d[k] = v
    def _addr_field(self, d, k, v): d[k] = v
    def _grp_field(self, d, k, v): d[k] = v
    def _svc_field(self, d, k, v): d[k] = v
    def _route_field(self, d, k, v): d[k] = v
    def _vpn_field(self, d, k, v): d[k] = v

    def get_summary(self, p):
        return {
            'device_type': 'FortiGate',
            'interfaces': len(p.get('interfaces', [])),
            'policies': len(p.get('policies', [])),
            'addresses': len(p.get('objects', {}).get('addresses', [])),
            'services': len(p.get('objects', {}).get('services', [])),
            'routes': len(p.get('routes', [])),
            'vpn_tunnels': len(p.get('vpn', [])),
        }
