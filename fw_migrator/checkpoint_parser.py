import re, json, ipaddress


class CheckpointParser:
    def parse(self, raw):
        result = {
            'interfaces': [], 'policies': [], 'routes': [], 'nat_rules': [], 'vpn_communities': [],
            'objects': {'addresses': [], 'address_groups': [], 'services': [], 'service_groups': []},
            'raw': raw
        }
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
        except:
            data = {'clish_config': raw}

        clish = data.get('clish_config', '')
        objects_raw = data.get('objects', '')
        rulebases_raw = data.get('rulebases', '')

        if clish and 'clish_error' not in clish:
            self._parse_clish(clish, result)
        if objects_raw and 'no_objects_file' not in objects_raw:
            self._parse_objects(objects_raw, result)
        if rulebases_raw and 'no_rulebases_file' not in rulebases_raw:
            self._parse_rulebases(rulebases_raw, result)
        return result

    def _parse_clish(self, config, result):
        for line in config.splitlines():
            s = line.strip()
            m = re.match(r'add interface (\S+) ipv4-address (\S+) mask-length (\d+)', s)
            if m:
                result['interfaces'].append({'name': m.group(1), 'ip': m.group(2), 'mask_length': m.group(3)}); continue
            m = re.match(r'set static-route (\S+)/(\d+) nexthop gateway address (\S+)', s)
            if m:
                result['routes'].append({'dst': m.group(1), 'prefix': m.group(2), 'gateway': m.group(3)}); continue
            m = re.match(r'add host name (\S+) ip-address (\S+)', s)
            if m:
                result['objects']['addresses'].append({'name': m.group(1), 'type': 'ipmask',
                    'subnet': m.group(2), 'subnet_mask': '255.255.255.255'}); continue
            m = re.match(r'add network name (\S+) subnet (\S+) mask-length (\d+)', s)
            if m:
                try: mask = str(ipaddress.IPv4Network(f'0.0.0.0/{m.group(3)}', strict=False).netmask)
                except: mask = '255.255.255.0'
                result['objects']['addresses'].append({'name': m.group(1), 'type': 'ipmask',
                    'subnet': m.group(2), 'subnet_mask': mask}); continue

    def _parse_objects(self, raw, result):
        for m in re.finditer(r'\(\s*:type \(host\)(.*?)\n\)', raw, re.DOTALL):
            c = m.group(0)
            nm = re.search(r':name \((\S+)\)', c); ip = re.search(r':ipaddr \((\S+)\)', c)
            if nm and ip:
                result['objects']['addresses'].append({'name': nm.group(1), 'type': 'ipmask',
                    'subnet': ip.group(1), 'subnet_mask': '255.255.255.255'})
        for m in re.finditer(r'\(\s*:type \(network\)(.*?)\n\)', raw, re.DOTALL):
            c = m.group(0)
            nm = re.search(r':name \((\S+)\)', c); ip = re.search(r':ipaddr \((\S+)\)', c)
            mk = re.search(r':netmask \((\S+)\)', c)
            if nm and ip and mk:
                result['objects']['addresses'].append({'name': nm.group(1), 'type': 'ipmask',
                    'subnet': ip.group(1), 'subnet_mask': mk.group(1)})
        for m in re.finditer(r'\(\s*:type \(group\)(.*?)\n\)', raw, re.DOTALL):
            c = m.group(0); nm = re.search(r':name \((\S+)\)', c)
            if nm:
                result['objects']['address_groups'].append({'name': nm.group(1),
                    'members': re.findall(r'\((\S+)\)', c)})

    def _parse_rulebases(self, raw, result):
        for i, m in enumerate(re.finditer(r'\(\s*:type \(rule\)(.*?)\n\)', raw, re.DOTALL), 1):
            c = m.group(0)
            src = re.findall(r':src \((.*?)\)', c); dst = re.findall(r':dst \((.*?)\)', c)
            act = re.search(r':action \((\S+)\)', c)
            result['policies'].append({'id': str(i), 'src': ' '.join(src) or 'any',
                'dst': ' '.join(dst) or 'any', 'action': act.group(1) if act else 'accept', 'service': 'ANY'})

    def get_summary(self, p):
        return {
            'device_type': 'CheckPoint',
            'interfaces': len(p.get('interfaces', [])),
            'policies': len(p.get('policies', [])),
            'addresses': len(p.get('objects', {}).get('addresses', [])),
            'services': len(p.get('objects', {}).get('services', [])),
            'routes': len(p.get('routes', [])),
            'nat_rules': len(p.get('nat_rules', [])),
            'vpn_communities': len(p.get('vpn_communities', [])),
        }
