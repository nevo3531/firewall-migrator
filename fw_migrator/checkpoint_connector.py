import paramiko
import time
import socket
import json


class CheckpointConnector:
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

    def _run(self, cmd, wait=2):
        stdin, stdout, stderr = self.client.exec_command(cmd, timeout=30)
        time.sleep(wait)
        return stdout.read().decode('utf-8', errors='replace')

    def test_connection(self):
        try:
            self._connect()
            out = self._run('fw ver')
            self.client.close()
            version = next((l.strip() for l in out.splitlines() if 'Check Point' in l or 'checkpoint' in l.lower()), out[:80])
            return {'success': True, 'device_type': 'CheckPoint',
                    'version': version, 'hostname': self.gateway,
                    'message': 'Connected to CheckPoint gateway'}
        except socket.timeout:
            return {'success': False, 'error': 'Connection timed out'}
        except paramiko.AuthenticationException:
            return {'success': False, 'error': 'Authentication failed'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            if self.client:
                try: self.client.close()
                except: pass

    def download_config(self):
        self._connect()
        try:
            parts = {
                'clish_config':  self._run('clish -c "show configuration" 2>/dev/null || echo clish_error', wait=5),
                'fw_stat':       self._run('fw policy stat 2>/dev/null || echo ""'),
                'objects':       self._run('cat $FWDIR/conf/objects_5_0.C 2>/dev/null | head -3000 || echo no_objects_file', wait=3),
                'rulebases':     self._run('cat $FWDIR/conf/rulebases_5_0.fws 2>/dev/null | head -3000 || echo no_rulebases_file', wait=3),
            }
            return json.dumps(parts)
        finally:
            self.client.close()
