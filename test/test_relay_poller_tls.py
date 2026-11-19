import importlib.util
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest

spec = importlib.util.spec_from_file_location('relay_poller', pathlib.Path(__file__).parents[1] / 'scripts/relay-poller.py')
poller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(poller)


class MailTlsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cert = cls.tmp.name + '/cert.pem'
        cls.key = cls.tmp.name + '/key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', cls.key, '-out', cls.cert, '-days', '1',
                        '-subj', '/CN=mail.fixture.invalid',
                        '-addext', 'subjectAltName=DNS:mail.fixture.invalid'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def connect(self, client_context, hostname):
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(self.cert, self.key)
        received = []
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(3)
            def serve():
                try:
                    raw, _ = listener.accept()
                    with raw:
                        with server_context.wrap_socket(raw, server_side=True) as tls:
                            received.append(tls.recv(64))
                except (ssl.SSLError, OSError):
                    pass
            thread = threading.Thread(target=serve)
            thread.start()
            try:
                with socket.create_connection(listener.getsockname(), timeout=3) as raw:
                    with client_context.wrap_socket(raw, server_hostname=hostname) as tls:
                        tls.sendall(b'fixture-login')
            finally:
                thread.join(4)
                self.assertFalse(thread.is_alive())
                self.received = received

    def test_untrusted_certificate_refused_before_credentials(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.connect(poller.imap_tls_context({}), 'mail.fixture.invalid')
        self.assertEqual(self.received, [])

    def test_wrong_hostname_refused_with_trusted_ca(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.connect(poller.imap_tls_context({'IMAP_CA_FILE': self.cert}), 'wrong.fixture.invalid')
        self.assertEqual(self.received, [])

    def test_correct_hostname_and_ca_allow_exchange(self):
        self.connect(poller.imap_tls_context({'IMAP_CA_FILE': self.cert}), 'mail.fixture.invalid')
        self.assertEqual(self.received, [b'fixture-login'])


if __name__ == '__main__':
    unittest.main()
