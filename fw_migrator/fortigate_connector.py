import paramiko
import time
import re
import socket


class FortiGateConnector:
    def __init__(self, gateway, username, password, port=22):
        self.gateway = gateway
        self.username = username
        self.password = password
        self.port = int(port)
        self.client = None

    def _connect(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            self.gateway, port=self.port, username=self.username,
            password=self.password, timeout=15,
            look_for_keys=False, allow_agent=False
        )

    def test_connection(self):
        try:
            self._connect()
            stdin, stdout, stderr = self.client.exec_command('get system status')
            output = stdout.read().decode('utf-8', errors='replace')
            self.client.close()
            version, hostname = 'Unknown', 'Unknown'
            for line in output.splitlines():
                if 'Version:' in line or 'Firmware Version:' in line:
                    version = line.split(':', 1)[-1].strip()
                if 'Hostname:' in line:
                    hostname = line.split(':', 1)[-1].strip()
            return {'success': True, 'device_type': 'FortiGate',
                    'version': version, 'hostname': hostname,
                    'message': f'Connected to {hostname} running {version}'}
        except socket.timeout:
            return {'success': False, 'error': 'Connection timed out'}
        except paramiko.AuthenticationException:
            return {'success': False, 'error': 'Authentication failed — check username/password'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            if self.client:
                try: self.client.close()
                except: pass

    def download_config(self):
        self._connect()
        try:
            channel = self.client.invoke_shell()
            time.sleep(1)
            channel.recv(65535)
            channel.send('config global\n')
            time.sleep(0.5)
            channel.send('show full-configuration\n')
            time.sleep(2)
            config_lines, timeout, start = [], 90, time.time()
            while time.time() - start < timeout:
                if channel.recv_ready():
                    chunk = channel.recv(65535).decode('utf-8', errors='replace')
                    config_lines.append(chunk)
                    if len(''.join(config_lines)) > 2_000_000:
                        break
                else:
                    time.sleep(0.3)
                    if config_lines and config_lines[-1].strip().endswith('#'):
                        break
            raw = ''.join(config_lines)
            raw = re.sub(r'\x1b\[[0-9;]*[mK]', '', raw)
            raw = re.sub(r'\x1b\[[\d;]*[A-Za-z]', '', raw)
            return raw
        finally:
            self.client.close()
