import http.client, json, os, shutil, stat, sys, tempfile, threading, time, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import linuxguard as lg
from http.server import ThreadingHTTPServer
POSIX = os.name != "nt"

class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), lg.H)
        cls.port = cls.srv.server_address[1]; cls.host = "127.0.0.1:%d" % cls.port
        lg.ALLOWED.add(cls.host); cls.tmp = tempfile.mkdtemp(); lg.LOGDIR = os.path.join(cls.tmp, "undo")
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
    @classmethod
    def tearDownClass(cls): cls.srv.shutdown(); shutil.rmtree(cls.tmp, True)
    def req(self, method, path, body=None, token=None, host=None, origin=None):
        time.sleep(0.35)  # the server rate-limits requests to one per 0.3 s
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = {"Host": host or self.host}
        if body is not None: h["Content-Type"] = "application/json"
        if token is not None: h["X-LG-Token"] = token
        if origin: h["Origin"] = origin
        c.request(method, path, json.dumps(body) if body is not None else None, h)
        r = c.getresponse(); data = r.read(); heads = dict(r.getheaders()); c.close()
        try: return r.status, json.loads(data), heads
        except ValueError: return r.status, data.decode(), heads
    def api(self, path, body): return self.req("POST", path, body, token=lg.TOKEN)[:2]
    def folder(self): return os.path.realpath(tempfile.mkdtemp(dir=self.tmp))

    def test_page_has_security_headers(self):
        st, body, h = self.req("GET", "/")
        self.assertEqual(st, 200); self.assertIn(lg.TOKEN, body)
        self.assertIn("nonce-", h["Content-Security-Policy"]); self.assertEqual(h["X-Frame-Options"], "DENY")
    def test_rejects_bad_host_token_origin(self):
        self.assertEqual(self.req("GET", "/", host="evil.example")[0], 403)
        self.assertEqual(self.req("POST", "/api/scan", {"path": "/"}, token="wrong")[0], 403)
        self.assertEqual(self.req("POST", "/api/scan", {"path": "/"}, token=lg.TOKEN, origin="http://evil.example")[0], 403)
    def test_scan_detects_private_key_content(self):
        d = self.folder(); open(os.path.join(d, "notes.txt"), "w").write("-----BEGIN RSA PRIVATE KEY-----\n")
        st, r = self.api("/api/scan", {"path": d, "depth": 1})
        self.assertEqual(st, 200); self.assertEqual(r["items"][0]["x"], "private key")
    def test_scan_rejects_non_folder(self):
        self.assertEqual(self.api("/api/scan", {"path": os.path.join(self.tmp, "nope")})[0], 400)
    @unittest.skipUnless(POSIX, "needs POSIX permissions")
    def test_refuses_unsafe_modes_and_traversal(self):
        d = self.folder(); open(os.path.join(d, "a.sh"), "w").close(); self.api("/api/scan", {"path": d})
        self.assertEqual(self.api("/api/plan", {"changes": [{"n": "a.sh", "mode": "4755"}]})[0], 400)
        self.assertEqual(self.api("/api/plan", {"changes": [{"n": "a.sh", "mode": "666"}]})[0], 400)
        self.assertEqual(self.api("/api/plan", {"changes": [{"n": "../x", "mode": "600"}]})[0], 400)
    @unittest.skipUnless(POSIX, "needs POSIX permissions")
    def test_never_changes_symlinks(self):
        d = self.folder(); os.symlink("/etc/hostname", os.path.join(d, "lnk")); self.api("/api/scan", {"path": d})
        self.assertEqual(self.api("/api/plan", {"changes": [{"n": "lnk", "mode": "600"}]})[0], 400)
    @unittest.skipUnless(POSIX, "needs POSIX permissions")
    def test_apply_then_undo_roundtrip(self):
        d = self.folder(); f = os.path.join(d, "a.sh"); open(f, "w").close(); os.chmod(f, 0o777)
        self.api("/api/scan", {"path": d})
        st, plan = self.api("/api/plan", {"changes": [{"n": "a.sh", "mode": "755"}]}); self.assertEqual(st, 200)
        self.assertEqual(self.api("/api/apply", {"code": plan["code"]})[1]["applied"], 1)
        self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), 0o755)
        self.assertEqual(self.api("/api/apply", {"code": plan["code"]})[0], 400)  # code is single-use
        self.assertEqual(self.api("/api/undo", {})[1]["restored"], 1)
        self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), 0o777)

    @unittest.skipUnless(POSIX, "needs POSIX permissions")
    def test_secure_chmod_refuses_symlinked_parent(self):
        d, other = self.folder(), self.folder(); f = os.path.join(other, "a.sh"); open(f, "w").close(); os.chmod(f, 0o644)
        os.symlink(other, os.path.join(d, "sub")); lg.ROOT[0] = d
        with self.assertRaises(OSError): lg.secure_chmod("sub/a.sh", 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), 0o644)
    @unittest.skipUnless(POSIX, "needs POSIX permissions")
    def test_secure_chmod_returns_previous_mode(self):
        d = self.folder(); os.mkdir(os.path.join(d, "s")); f = os.path.join(d, "s", "a"); open(f, "w").close(); os.chmod(f, 0o666); lg.ROOT[0] = d
        self.assertEqual(lg.secure_chmod("s/a", 0o600), 0o666); self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), 0o600)

if __name__ == "__main__": unittest.main()
