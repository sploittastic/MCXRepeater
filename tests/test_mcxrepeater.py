import http.cookiejar
import json
import os
import struct
import sys
import tempfile
import threading
import time
import unittest
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import mcxrepeater as mx  # noqa: E402

KEY = "11" * 32


def config(**over):
    c = mx.normalise(dict(private_key=KEY, **over))
    c["radio1"]["repeat_cross"] = True
    c["radio2"] = dict(c["radio2"], enabled=True, repeat_cross=True)
    return mx.normalise(c)


def repeater(**over):
    return mx.Repeater(config(**over))


def flood(ptype, payload, path=b"", hash_size=1, scoped_code=None):
    p = mx.Packet(ptype, payload)
    p.header = (p.header & ~0x03) | (mx.ROUTE_TRANSPORT_FLOOD if scoped_code is not None else mx.ROUTE_FLOOD)
    if scoped_code is not None:
        p.transport_codes = (scoped_code, 0)
    p.path = path
    p.path_len = ((hash_size - 1) << 6) | (len(path) // hash_size)
    return p.encode()


def direct(ptype, payload, path, hash_size=1):
    p = mx.Packet(ptype, payload)
    p.header = (p.header & ~0x03) | mx.ROUTE_DIRECT
    p.path = path
    p.path_len = ((hash_size - 1) << 6) | (len(path) // hash_size)
    return p.encode()


def queued(app, i):
    return [mx.Packet.parse(e[3]) for e in sorted(app.radios[i].heap)]


TXT = bytes([0xAA, 0x5B]) + bytes(18)          # dest AA, src 5B, mac + ciphertext


class ConfigTests(unittest.TestCase):
    def test_example_config_is_valid(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "config.example.json")) as f:
            c = mx.normalise(json.load(f))
        self.assertEqual(c["radio1"]["sf"], 7)
        self.assertEqual(set(c), set(mx.DEFAULT_CONFIG))

    def test_settings_validation(self):
        c = config()
        with self.assertRaises(ValueError):
            mx.apply_settings(c, {"radio1": {"bw_khz": 100}})
        with self.assertRaises(ValueError):
            mx.apply_settings(c, {"blacklist": {"prefixes": ["zz*"]}})
        with self.assertRaises(ValueError):
            mx.apply_settings(c, {"web_password": "x"})
        with self.assertRaises(ValueError):
            mx.apply_settings(c, {"lat": 10})                       # lon missing
        n = mx.apply_settings(c, {"blacklist": {"prefixes": ["5B98", "5b*"]}, "regions": {"list": ["#usa-ca"]}})
        self.assertEqual(n["blacklist"]["prefixes"], ["5b98*", "5b*"])
        self.assertEqual(n["regions"]["list"], ["usa-ca"])
        n2 = mx.apply_settings(n, {"blacklist": {"prefixes": []}})
        self.assertEqual(n2["blacklist"]["prefixes"], [])             # lists replace, not merge
        self.assertEqual(c["blacklist"]["prefixes"], [])              # the old config is untouched

    def test_password_hash(self):
        h = mx.hash_web_password("secret1")
        self.assertTrue(mx.check_web_password("secret1", h))
        self.assertFalse(mx.check_web_password("secret2", h))

    def test_generated_key_round_trips(self):
        k = mx.generate_private_key()
        self.assertEqual(len(k), 128)
        ident = mx.RepeaterIdentity(bytes.fromhex(k))
        sig = ident.sign(b"hello")
        self.assertTrue(mx.ed25519_verify(ident.pub_key, sig, b"hello"))


class FloodTests(unittest.TestCase):
    def test_cross_band_relay_and_shared_dedupe(self):
        app = repeater()
        raw = flood(mx.PT_TXT_MSG, TXT, path=b"\x42")
        app.on_rx(0, raw, 5.0, -90)
        for i in (0, 1):
            q = queued(app, i)
            self.assertEqual(len(q), 1)
            self.assertEqual(q[0].path, b"\x42" + app.ident.pub_key[:1])
            self.assertEqual(q[0].hop_count, 2)
        # the same packet comes back on the other band via another repeater: dropped
        app.on_rx(1, flood(mx.PT_TXT_MSG, TXT, path=b"\x42\x77\x88"), 5.0, -90)
        self.assertEqual(len(queued(app, 0)), 1)
        self.assertEqual(app.stats["drop_duplicate"], 1)

    def test_same_only(self):
        app = repeater()
        app.cfg = mx.apply_settings(app.cfg, {"radio1": {"repeat_cross": False}})
        app.on_rx(0, flood(mx.PT_TXT_MSG, TXT), 0, 0)
        self.assertEqual((len(queued(app, 0)), len(queued(app, 1))), (1, 0))

    def test_cross_only_and_off(self):
        app = repeater()
        app.cfg = mx.apply_settings(app.cfg, {"radio1": {"repeat_same": False}})
        app.on_rx(0, flood(mx.PT_TXT_MSG, TXT), 0, 0)
        self.assertEqual((len(queued(app, 0)), len(queued(app, 1))), (0, 1))
        app.cfg = mx.apply_settings(app.cfg, {"radio1": {"repeat_cross": False}})
        app.on_rx(0, flood(mx.PT_TXT_MSG, TXT[:2] + b"\x01" * 18), 0, 0)
        self.assertEqual(app.stats["drop_repeat_off"], 1)

    def test_two_byte_path_ids(self):
        app = repeater()
        app.on_rx(0, flood(mx.PT_TXT_MSG, TXT, path=b"\x42\x43", hash_size=2), 0, 0)
        q = queued(app, 0)[0]
        self.assertEqual(q.hash_size, 2)
        self.assertEqual(q.path, b"\x42\x43" + app.ident.pub_key[:2])

    def test_hops_and_loop(self):
        app = repeater(max_flood_hops=3)
        app.on_rx(0, flood(mx.PT_TXT_MSG, TXT, path=b"\x01\x02\x03"), 0, 0)
        self.assertEqual(app.stats["drop_hops"], 1)
        app = repeater(loop_detect="strict")
        me = app.ident.pub_key[:1]
        app.on_rx(0, flood(mx.PT_TXT_MSG, TXT, path=me + b"\x02"), 0, 0)
        self.assertEqual(app.stats["drop_loop"], 1)

    def test_regions(self):
        app = repeater(regions={"mode": "only", "list": ["usa-ca"], "relay_unscoped": False})
        pkt = mx.Packet(mx.PT_TXT_MSG, TXT)
        code_ca = mx.transport_code(mx.transport_key("usa-ca"), pkt)
        code_or = mx.transport_code(mx.transport_key("usa-or"), pkt)
        app.on_rx(0, flood(mx.PT_TXT_MSG, TXT, scoped_code=code_ca), 0, 0)
        self.assertEqual(app.stats["relayed"], 1)
        app.on_rx(0, flood(mx.PT_TXT_MSG, TXT[:2] + b"\x02" * 18, scoped_code=code_or), 0, 0)
        app.on_rx(0, flood(mx.PT_TXT_MSG, TXT[:2] + b"\x03" * 18), 0, 0)    # unscoped, not relayed here
        self.assertEqual(app.stats["drop_region"], 2)
        app.cfg = mx.apply_settings(app.cfg, {"regions": {"mode": "except", "relay_unscoped": True}})
        pl = TXT[:2] + b"\x04" * 18
        app.on_rx(0, flood(mx.PT_TXT_MSG, pl, scoped_code=mx.transport_code(mx.transport_key("usa-ca"), mx.Packet(mx.PT_TXT_MSG, pl))), 0, 0)
        app.on_rx(0, flood(mx.PT_TXT_MSG, TXT[:2] + b"\x05" * 18), 0, 0)
        self.assertEqual((app.stats["drop_region"], app.stats["relayed"]), (3, 2))

    def test_packet_types(self):
        app = repeater(packet_types={"mode": "except", "list": ["GRP_TXT"]})
        app.on_rx(0, flood(mx.PT_GRP_TXT, b"\x11" * 20), 0, 0)
        app.on_rx(0, flood(mx.PT_TXT_MSG, TXT), 0, 0)
        self.assertEqual((app.stats["drop_packet_type"], app.stats["relayed"]), (1, 1))
        app = repeater(packet_types={"mode": "only", "list": ["ADVERT"]})
        app.on_rx(0, flood(mx.PT_TXT_MSG, TXT), 0, 0)
        self.assertEqual(app.stats["drop_packet_type"], 1)

    def test_kill_switch(self):
        app = repeater(relay_enabled=False)
        app.on_rx(0, flood(mx.PT_TXT_MSG, TXT), 0, 0)
        self.assertEqual(app.stats["drop_relay_off"], 1)


class AdvertTests(unittest.TestCase):
    def other(self):
        return mx.RepeaterIdentity(bytes.fromhex("22" * 32))

    def test_advert_relayed_and_neighbour_learned(self):
        app = repeater()
        adv = mx.make_advert(self.other(), "Hilltop", 37.5, -122.1)
        app.on_rx(1, flood(mx.PT_ADVERT, adv.payload), 7.5, -80)
        self.assertEqual(app.stats["relayed"], 1)
        self.assertEqual(app.neighbour_radios(self.other().pub_key[:1]), {1})
        self.assertEqual(app.make_snapshot()["neighbours"][0]["name"], "Hilltop")

    def test_forged_advert_dropped(self):
        app = repeater()
        p = bytearray(mx.make_advert(self.other(), "Hilltop", None, None).payload)
        p[-1] ^= 1
        app.on_rx(0, flood(mx.PT_ADVERT, bytes(p)), 0, 0)
        self.assertEqual(app.stats["drop_bad_signature"], 1)

    def test_own_advert_not_relayed_and_send_advert(self):
        app = repeater()
        app.cfg = mx.apply_settings(app.cfg, {"radio2": {"hash_mode": 1}})
        self.assertEqual(app.send_advert(True), ["radio1", "radio2"])
        a1, a2 = queued(app, 0)[0], queued(app, 1)[0]
        self.assertTrue(a1.is_flood)
        self.assertEqual((a1.hash_size, a2.hash_size), (1, 2))
        self.assertEqual(mx.advert_info(a1.payload), (mx.ADV_TYPE_REPEATER, "MCX Repeater"))
        app.on_rx(0, flood(mx.PT_ADVERT, a1.payload, path=b"\x99"), 0, 0)
        self.assertEqual(app.stats["relayed"], 0)


class BlacklistTests(unittest.TestCase):
    def test_full_key_prefix_on_adverts(self):
        other = mx.RepeaterIdentity(bytes.fromhex("22" * 32))
        pre = other.pub_key.hex()[:4] + "*"
        app = repeater(blacklist={"prefixes": [pre]})
        app.on_rx(0, flood(mx.PT_ADVERT, mx.make_advert(other, "x", None, None).payload), 0, 0)
        self.assertEqual(app.stats["drop_blacklist"], 1)

    def test_dm_source_byte(self):
        app = repeater(blacklist={"prefixes": ["5b98*"]})
        app.on_rx(0, flood(mx.PT_TXT_MSG, TXT), 0, 0)
        self.assertEqual(app.stats["relayed"], 1)                     # a 2-byte prefix can't be checked on a DM
        app = repeater(blacklist={"prefixes": ["5b*"]})
        app.on_rx(0, flood(mx.PT_TXT_MSG, TXT), 0, 0)
        self.assertEqual(app.stats["drop_blacklist"], 1)

    def test_channel_name(self):
        key = mx.channel_secret("#test")
        def msg(text, n):
            plain = struct.pack("<I", n) + b"\x00" + text
            return bytes([mx.hashlib.sha256(key).digest()[0]]) + mx.encrypt_then_mac(key + bytes(16), plain)
        app = repeater(blacklist={"channel_names": [{"channel": "test", "name": "Spammer"}]})
        app.on_rx(0, flood(mx.PT_GRP_TXT, msg(b"spammer: buy now", 1)), 0, 0)
        app.on_rx(0, flood(mx.PT_GRP_TXT, msg(b"Alice: hi", 2)), 0, 0)
        self.assertEqual((app.stats["drop_blacklist"], app.stats["relayed"]), (1, 1))


class DirectTests(unittest.TestCase):
    def test_direct_follows_neighbour(self):
        app = repeater()
        me = app.ident.pub_key[:1]
        app.note_neighbour(b"\x77", 1, 3.0)
        app.on_rx(0, direct(mx.PT_TXT_MSG, TXT, me + b"\x77"), 0, 0)
        self.assertEqual(len(queued(app, 0)), 0)
        q = queued(app, 1)
        self.assertEqual((q[0].path, q[0].hop_count), (b"\x77", 1))

    def test_direct_unknown_goes_both(self):
        app = repeater()
        me = app.ident.pub_key[:1]
        app.on_rx(0, direct(mx.PT_TXT_MSG, TXT, me + b"\x66"), 0, 0)
        self.assertEqual((len(queued(app, 0)), len(queued(app, 1))), (1, 1))

    def test_last_hop_uses_destination_hash(self):
        app = repeater()
        me = app.ident.pub_key[:1]
        app.note_neighbour(b"\xaa" + b"\x00" * 31, 0, 3.0)            # destination AA heard zero-hop on radio1
        app.on_rx(1, direct(mx.PT_TXT_MSG, TXT, me), 0, 0)
        self.assertEqual((len(queued(app, 0)), len(queued(app, 1))), (1, 0))

    def test_not_for_us_and_ack(self):
        app = repeater()
        me = app.ident.pub_key[:1]
        other = bytes([me[0] ^ 0xFF])
        app.on_rx(0, direct(mx.PT_TXT_MSG, TXT, other + b"\x01"), 0, 0)
        self.assertEqual(app.stats["drop_not_for_us"], 1)
        app.on_rx(0, direct(mx.PT_ACK, b"\x01\x02\x03\x04", me + b"\x09"), 0, 0)
        q = queued(app, 0)[0]
        self.assertEqual((q.ptype, q.path), (mx.PT_ACK, b"\x09"))
        self.assertEqual(app.stats["relayed_ack"], 1)

    def test_trace(self):
        app = repeater()
        me = app.ident.pub_key[:1]
        payload = struct.pack("<II", 1, 2) + b"\x00" + me + b"\x55"     # route: us, then 55
        p = mx.Packet(mx.PT_TRACE, payload)
        p.header = (p.header & ~0x03) | mx.ROUTE_DIRECT
        app.note_neighbour(b"\x55", 1, 0)
        app.on_rx(0, p.encode(), 6.25, -70)
        q = queued(app, 1)[0]
        self.assertEqual((q.path_len, q.path), (1, bytes([25])))
        self.assertEqual(len(queued(app, 0)), 0)

    def test_discovery_answered_on_arrival_radio(self):
        app = repeater()
        p = mx.Packet(mx.PT_CONTROL, bytes([0x80, 1 << mx.ADV_TYPE_REPEATER]) + b"\x01\x02\x03\x04")
        p.header = (p.header & ~0x03) | mx.ROUTE_DIRECT
        app.on_rx(1, p.encode(), 0, 0)
        q = queued(app, 1)
        self.assertEqual(len(q), 1)
        self.assertEqual(q[0].payload[6:6 + 32], app.ident.pub_key)
        self.assertEqual(len(queued(app, 0)), 0)


class FakeModem:
    def __init__(self, port, baud, events):
        self.events, self.sent, self.params, self.closed = events, [], None, False
        FakeModem.last = self

    def command(self, sub, data=b"", timeout=2.0):
        if sub == 0x09:
            self.params = struct.unpack("<IIBB", data)
        if sub == 0x0B:
            return struct.pack("<IIBB", *self.params) if self.params else None
        return b""

    def set_param(self, cmd, value):
        pass

    def send_packet(self, raw):
        self.sent.append(raw)
        threading.Timer(0.01, self.events.put, (("txdone", True),)).start()

    def close(self):
        self.closed = True


class ThreadedTests(unittest.TestCase):
    def test_end_to_end_with_fake_modems(self):
        c = config()
        c = mx.normalise(dict(c, radio1=dict(c["radio1"], sf=5, bw_khz=500), radio2=dict(c["radio2"], sf=5, bw_khz=500)))
        app = mx.Repeater(c, modem_factory=FakeModem)
        app.next_zero_advert = app.next_flood_advert = time.monotonic() + 999
        app.start()
        try:
            deadline = time.time() + 5
            while time.time() < deadline and not all(r.status == "ok" for r in app.radios):
                time.sleep(0.02)
            self.assertEqual([r.status for r in app.radios], ["ok", "ok"])
            app.radios[0].put(("rx", flood(mx.PT_TXT_MSG, TXT), 4.0, -95))
            deadline = time.time() + 5
            while time.time() < deadline and sum(r.stats["tx"] for r in app.radios) < 2:
                time.sleep(0.02)
            self.assertEqual([r.stats["tx"] for r in app.radios], [1, 1])
            self.assertEqual(app.radios[0].modem.params[0], int(c["radio1"]["freq_mhz"] * 1e6))
        finally:
            app.stop()


class WebTests(unittest.TestCase):
    def test_login_and_settings(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "config.json")
        c = config(listen_address="127.0.0.1", listen_port=18765, web_password="hunter22")
        mx.save_config(path, c)
        c = mx.prepare_config(path)
        self.assertTrue(c["web_password"].startswith("pbkdf2_sha256$"))
        app = mx.Repeater(c, path)
        app.snapshot = app.make_snapshot()
        web = mx.WebUI(app)
        try:
            jar = http.cookiejar.CookieJar()
            op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
            base = "http://127.0.0.1:18765/"

            def post(u, body):
                req = urllib.request.Request(base + u, json.dumps(body).encode(), {"Content-Type": "application/json"})
                try:
                    r = op.open(req)
                    return r.status, json.loads(r.read())
                except urllib.error.HTTPError as e:
                    return e.code, json.loads(e.read())

            self.assertIn(b"mcxrepeater", op.open(base).read())
            st = json.loads(op.open(base + "api/state").read())
            self.assertFalse(st["admin"])
            self.assertNotIn("settings", st)
            self.assertEqual(post("api/settings", {"name": "X"})[0], 401)
            self.assertEqual(post("api/login", {"password": "hunter22"})[0], 200)
            code, r = post("api/settings", {"name": "Ridge", "radio2": {"freq_mhz": 915.0}})
            self.assertEqual(code, 200, r)
            self.assertEqual(r["settings"]["radio2"]["freq_mhz"], 915.0)
            self.assertNotIn("private_key", r["settings"])
            with open(path) as f:
                saved = json.load(f)
            self.assertEqual((saved["name"], saved["radio2"]["freq_mhz"]), ("Ridge", 915.0))
            self.assertEqual(post("api/settings", {"radio1": {"sf": 13}})[0], 400)
            code, r = post("api/identity", {"generate": True})
            self.assertEqual(code, 200)
            self.assertEqual(r["pub"], app.ident.pub_key.hex())
            with open(path) as f:
                self.assertEqual(mx.RepeaterIdentity(bytes.fromhex(json.load(f)["private_key"])).pub_key.hex(), r["pub"])
        finally:
            web.server.shutdown()
            web.server.server_close()


if __name__ == "__main__":
    unittest.main()
