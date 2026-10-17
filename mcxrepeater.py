#!/usr/bin/env python3
"""
mcxrepeater.py - a two-radio MeshCore repeater for Linux (e.g. a Raspberry Pi), using MeshCore KISS modems
(examples/kiss_modem firmware) as the radios.

Each radio can repeat on its own frequency ("same frequency") and/or onto the other radio ("cross frequency").
Both radios share one repeater identity and one duplicate table, so a packet is relayed at most once per radio
whichever band it arrives on. The relay rules follow the firmware (Mesh.cpp, simple_repeater MyMesh.cpp), as
pyMeshRoom's virtual repeater does; this file reuses that code.

Threads: one reader per radio (inside KissModem), one evaluator (owns all routing state: duplicates, neighbours,
filters, stats), one transmitter per radio (modem setup, scheduled sends, waits for TxDone), and the web server.

Requirements:  python3 >= 3.9, pyserial, cryptography
    sudo apt install python3-serial python3-cryptography

Usage:
    cp config.example.json config.json      # then edit serial ports, frequencies and web_password
    python3 mcxrepeater.py --config config.json
"""

import argparse
import base64
import collections
import copy
import gzip
import hashlib
import heapq
import hmac
import itertools
import json
import logging
import math
import os
import queue
import random
import re
import secrets
import struct
import sys
import threading
import time

try:
    import serial
except ImportError:
    sys.exit("pyserial missing:  sudo apt install python3-serial")
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.exit("cryptography missing:  sudo apt install python3-cryptography")

log = logging.getLogger("mcxrepeater")
VERSION = "mcxrepeater 1.0"

# ============================================================================
# MeshCore constants
# ============================================================================

PUB_KEY_SIZE = 32
SIGNATURE_SIZE = 64
CIPHER_MAC_SIZE = 2
CIPHER_BLOCK_SIZE = 16
MAX_PACKET_PAYLOAD = 184
MAX_PATH_SIZE = 64
MAX_ADVERT_DATA_SIZE = 32

ROUTE_TRANSPORT_FLOOD, ROUTE_FLOOD, ROUTE_DIRECT, ROUTE_TRANSPORT_DIRECT = 0, 1, 2, 3

PT_REQ, PT_RESPONSE, PT_TXT_MSG, PT_ACK, PT_ADVERT, PT_GRP_TXT, PT_GRP_DATA, PT_ANON_REQ, \
    PT_PATH, PT_TRACE, PT_MULTIPART, PT_CONTROL = range(12)
PT_RAW_CUSTOM = 0x0F
PT_NAMES = {PT_REQ: "REQ", PT_RESPONSE: "RESPONSE", PT_TXT_MSG: "TXT_MSG", PT_ACK: "ACK", PT_ADVERT: "ADVERT",
            PT_GRP_TXT: "GRP_TXT", PT_GRP_DATA: "GRP_DATA", PT_ANON_REQ: "ANON_REQ", PT_PATH: "PATH",
            PT_TRACE: "TRACE", PT_MULTIPART: "MULTIPART", PT_CONTROL: "CONTROL", PT_RAW_CUSTOM: "RAW_CUSTOM"}
PT_BY_NAME = {v: k for k, v in PT_NAMES.items()}
ROUTE_NAMES = {ROUTE_TRANSPORT_FLOOD: "flood (scoped)", ROUTE_FLOOD: "flood", ROUTE_DIRECT: "direct",
               ROUTE_TRANSPORT_DIRECT: "direct (scoped)"}

ADV_TYPE_REPEATER = 2
ADV_LATLON_MASK, ADV_NAME_MASK = 0x10, 0x80
PUBLIC_CHANNEL_KEY = base64.b64decode("izOH6cXN6mrJ5e26oRXNcg==")

RPT_FLOOD_MAX_ADVERT = 8              # firmware flood.max.advert
RPT_TX_DELAY_FACTOR = 0.5             # firmware tx_delay_factor (floods)
RPT_DIRECT_TX_DELAY_FACTOR = 0.3      # firmware direct_tx_delay_factor
RPT_MAX_QUEUED = 16                   # relays waiting to go out per radio (the firmware's packet pool is 32)
RPT_LOOP_MAX = {"minimal": {1: 4, 2: 2, 3: 1}, "moderate": {1: 2, 2: 1, 3: 1}, "strict": {1: 1, 2: 1, 3: 1}}
SEEN_MAX = 4096                       # duplicate table entries (shared by both radios)
NEIGHBOUR_TTL_S = 12 * 3600           # a neighbour heard this recently decides which radio a direct packet uses
NEIGHBOURS_MAX = 500
LOG_MAX = 300                         # recent packets kept for the web UI
TXBUSY_RETRIES = 5

def path_bytes(path_len):
    return (path_len & 63) * ((path_len >> 6) + 1)


def path_valid(path_len):
    return ((path_len >> 6) + 1) != 4 and path_bytes(path_len) <= MAX_PATH_SIZE


def path_hops(path_len):
    return 0xFF if path_len is None else (path_len & 63)


def hexs(b):
    return b.hex().upper()


def now_s():
    return int(time.time())


# ============================================================================
# Crypto (AES-128-ECB + truncated HMAC-SHA256, exactly as MeshCore Utils.cpp)
# ============================================================================

def sha256(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def aes_encrypt(secret, data):
    if len(data) % 16:
        data = data + bytes(16 - len(data) % 16)          # zero padding
    enc = Cipher(algorithms.AES(secret[:16]), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()


def aes_decrypt(secret, data):
    dec = Cipher(algorithms.AES(secret[:16]), modes.ECB()).decryptor()
    return dec.update(data) + dec.finalize()


def encrypt_then_mac(secret, plaintext):
    ct = aes_encrypt(secret, plaintext)
    mac = hmac.new(secret[:PUB_KEY_SIZE], ct, hashlib.sha256).digest()[:CIPHER_MAC_SIZE]
    return mac + ct


def mac_then_decrypt(secret, data):
    if len(data) <= CIPHER_MAC_SIZE:
        return None
    ct = data[CIPHER_MAC_SIZE:]
    if len(ct) % CIPHER_BLOCK_SIZE:
        return None
    mac = hmac.new(secret[:PUB_KEY_SIZE], ct, hashlib.sha256).digest()[:CIPHER_MAC_SIZE]
    if not hmac.compare_digest(mac, data[:CIPHER_MAC_SIZE]):
        return None
    return aes_decrypt(secret, ct)


def ed25519_verify(pub, sig, msg):
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


_P = 2 ** 255 - 19





# Ed25519 signing from an expanded key [scalar || prefix], as MeshCore stores private keys (orlp ed25519). The
# cryptography package only signs from a 32-byte seed, and a firmware key can't be turned back into one.
_ED_D = -121665 * pow(121666, _P - 2, _P) % _P
_ED_L = 2 ** 252 + 27742317777372353535851937790883648493


def _ed_add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _ED_D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _ed_mul(s, p):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _ed_add(q, p)
        p = _ed_add(p, p)
        s >>= 1
    return q


def _ed_encode(p):
    zi = pow(p[2], _P - 2, _P)
    x, y = p[0] * zi % _P, p[1] * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed_base():
    y = 4 * pow(5, _P - 2, _P) % _P
    x2 = (y * y - 1) * pow(_ED_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    if x & 1:
        x = _P - x
    return (x, y, 1, x * y % _P)


_ED_B = _ed_base()


class RepeaterIdentity:
    """The repeater's key, from the config: a 32-byte seed or a 64-byte MeshCore private key."""

    def __init__(self, key):
        if len(key) == 32:
            h = bytearray(hashlib.sha512(key).digest())
            h[0] &= 248; h[31] &= 127; h[31] |= 64
            key = bytes(h)
        if len(key) != 64:
            raise ValueError("private key: 32 or 64 bytes of hex")
        self._a = int.from_bytes(key[:32], "little") & ((1 << 255) - 1)
        self._prefix = key[32:]
        self.pub_key = _ed_encode(_ed_mul(self._a, _ED_B))

    def sign(self, msg):
        r = int.from_bytes(hashlib.sha512(self._prefix + msg).digest(), "little") % _ED_L
        big_r = _ed_encode(_ed_mul(r, _ED_B))
        h = int.from_bytes(hashlib.sha512(big_r + self.pub_key + msg).digest(), "little") % _ED_L
        return big_r + ((r + h * self._a) % _ED_L).to_bytes(32, "little")


def transport_key(region):
    """MeshCore auto (hashtag) region key: SHA-256 of "#name", first 16 bytes (TransportKeyStore::getAutoKeyFor;
    RegionMap treats a plain name as "#name"). "$" private regions need a key store, which the firmware lacks too."""
    name = region if region.startswith("#") else "#" + region
    return hashlib.sha256(name.encode()).digest()[:16]


def transport_code(key, pkt):
    """TransportKey::calcTransportCode: HMAC-SHA256(key, type || payload), first 2 bytes little-endian;
    0000 and FFFF are reserved."""
    code = struct.unpack("<H", hmac.new(key, bytes([pkt.ptype]) + pkt.payload, hashlib.sha256).digest()[:2])[0]
    return 1 if code == 0 else 0xFFFE if code == 0xFFFF else code


# ============================================================================
# Packet
# ============================================================================

class Packet:
    __slots__ = ("header", "transport_codes", "path_len", "path", "payload", "snr", "rssi", "raw_len")

    def __init__(self, ptype=0, payload=b""):
        self.header = (ptype & 0x0F) << 2
        self.transport_codes = (0, 0)
        self.path_len = 0
        self.path = b""
        self.payload = payload
        self.snr = 0.0
        self.rssi = 0
        self.raw_len = 0

    route_type = property(lambda s: s.header & 0x03)
    ptype = property(lambda s: (s.header >> 2) & 0x0F)
    is_flood = property(lambda s: s.route_type in (ROUTE_FLOOD, ROUTE_TRANSPORT_FLOOD))
    is_direct = property(lambda s: s.route_type in (ROUTE_DIRECT, ROUTE_TRANSPORT_DIRECT))
    has_transport = property(lambda s: s.route_type in (ROUTE_TRANSPORT_FLOOD, ROUTE_TRANSPORT_DIRECT))
    hash_size = property(lambda s: (s.path_len >> 6) + 1)
    hop_count = property(lambda s: s.path_len & 63)

    @classmethod
    def parse(cls, raw):
        if not raw or len(raw) < 2:
            return None                                     # empty / truncated (e.g. a bad observer message)
        p = cls()
        i = 0
        p.header = raw[i]; i += 1
        if p.has_transport:
            if len(raw) < i + 4:
                return None
            p.transport_codes = struct.unpack_from("<HH", raw, i); i += 4
        if len(raw) <= i:
            return None
        p.path_len = raw[i]; i += 1
        if not path_valid(p.path_len):
            return None
        bl = path_bytes(p.path_len)
        p.path = bytes(raw[i:i + bl]); i += bl
        if i >= len(raw):
            return None
        p.payload = bytes(raw[i:])
        if len(p.payload) > MAX_PACKET_PAYLOAD:
            return None
        p.raw_len = len(raw)
        return p

    def encode(self):
        out = bytearray([self.header])
        if self.has_transport:
            out += struct.pack("<HH", *self.transport_codes)
        out.append(self.path_len)
        out += self.path[:path_bytes(self.path_len)]
        out += self.payload
        return bytes(out)

    def packet_hash(self):
        h = hashlib.sha256()
        h.update(bytes([self.ptype]))
        if self.ptype == PT_TRACE:
            h.update(struct.pack("<H", self.path_len))
        h.update(self.payload)
        return h.digest()[:8]

    def raw_length(self):
        return 2 + path_bytes(self.path_len) + len(self.payload) + (4 if self.has_transport else 0)

    def copy(self):
        p = Packet()
        p.header, p.transport_codes, p.path_len, p.path, p.payload = self.header, self.transport_codes, self.path_len, self.path, self.payload
        p.snr, p.rssi, p.raw_len = self.snr, self.rssi, self.raw_len
        return p


# ============================================================================
# KISS modem driver
# ============================================================================

FEND, FESC, TFEND, TFESC = 0xC0, 0xDB, 0xDC, 0xDD
HW_TXDONE, HW_RXMETA, HW_OK, HW_ERROR = 0xF8, 0xF9, 0xF0, 0xF1


class KissModem:
    """Serial KISS link. A reader thread decodes frames: received packets (with their
    RxMeta SNR/RSSI) and TxDone events go to the main event queue; command responses
    wake the caller of command()."""

    def __init__(self, port, baud, events):
        # exclusive: a second program on the same port (another repeater, ModemManager) fails here with a clear error
        # instead of both reading it ("device reports readiness to read but returned no data")
        # DTR up (nRF52 boards like the RAK4631 only send over USB once DTR is up), RTS down: on an ESP32-S3's
        # native USB (Heltec V3/V4 "USB JTAG/serial debug unit") RTS is wired to reset, and a reset drops the device
        self.ser = serial.Serial(timeout=0.2, exclusive=True)
        self.ser.port, self.ser.baudrate = port, baud
        self.ser.dtr, self.ser.rts = True, False
        self.ser.open()
        self.events = events
        self._wlock = threading.Lock()
        self._cmd_lock = threading.Lock()
        self._resp_evt = threading.Event()
        self._resp_sub = None
        self._resp_data = None
        self._pending_rx = None
        self._async_pending = set()
        self._running = True
        threading.Thread(target=self._reader, name="kiss-rx", daemon=True).start()

    def close(self):
        self._running = False
        try:
            self.ser.close()
        except Exception:
            pass

    @staticmethod
    def _escape(data):
        out = bytearray()
        for b in data:
            if b == FEND:
                out += bytes([FESC, TFEND])
            elif b == FESC:
                out += bytes([FESC, TFESC])
            else:
                out.append(b)
        return bytes(out)

    def _write_frame(self, type_byte, data=b""):
        frame = bytes([FEND, type_byte]) + self._escape(data) + bytes([FEND])
        with self._wlock:
            self.ser.write(frame)

    def send_packet(self, raw):
        self._write_frame(0x00, raw)

    def set_param(self, cmd, value):
        self._write_frame(cmd, bytes([value & 0xFF]))

    def request(self, sub, data=b""):
        """Fire-and-forget SetHardware request: the reply arrives as an ("hw", sub, body) event."""
        with self._wlock:
            self._async_pending.add(sub | 0x80)
        self._write_frame(0x06, bytes([sub]) + data)

    def command(self, sub, data=b"", timeout=2.0):
        """SetHardware request/response. Returns the response data, or None on error/timeout."""
        with self._cmd_lock:
            self._resp_evt.clear()
            self._resp_sub = sub
            self._resp_data = None
            self._write_frame(0x06, bytes([sub]) + data)
            if not self._resp_evt.wait(timeout):
                self._resp_sub = None
                return None
            self._resp_sub = None
            return self._resp_data

    def _flush_rx(self, snr=0.0, rssi=0):
        if self._pending_rx is not None:
            self.events.put(("rx", self._pending_rx, snr, rssi))
            self._pending_rx = None

    def _on_frame(self, frame):
        if not frame:
            return
        t = frame[0] & 0x0F
        data = frame[1:]
        if t == 0x00:
            self._flush_rx()                      # previous packet had no RxMeta
            self._pending_rx = bytes(data)
            return
        if t != 0x06 or not data:
            return
        sub, body = data[0], data[1:]
        if sub == HW_RXMETA:
            snr = struct.unpack("b", body[0:1])[0] / 4.0 if len(body) >= 1 else 0.0
            rssi = struct.unpack("b", body[1:2])[0] if len(body) >= 2 else 0
            self._flush_rx(snr, rssi)
            return
        self._flush_rx()
        if sub == HW_TXDONE:
            self.events.put(("txdone", bool(body and body[0])))
            return
        if sub in self._async_pending and (self._resp_sub is None or sub != (self._resp_sub | 0x80)):
            self._async_pending.discard(sub)                # reply to a fire-and-forget request
            self.events.put(("hw", sub, bytes(body)))
            return
        want = self._resp_sub
        if want is None and sub == HW_ERROR and self._async_pending:
            self._async_pending.clear()
            self.events.put(("hw", sub, bytes(body)))
            return
        if want is not None:
            if sub == (want | 0x80) or sub == HW_OK:
                self._resp_data = bytes(body)
                self._resp_evt.set()
            elif sub == HW_ERROR:
                if body and body[0] == 0x07:      # TxBusy can also answer a data frame
                    self.events.put(("txbusy",))
                self._resp_data = None
                self._resp_evt.set()
        elif sub == HW_ERROR and body and body[0] == 0x07:
            self.events.put(("txbusy",))

    def _reader(self):
        buf = bytearray()
        in_frame = esc = False
        while self._running:
            try:
                # wait for the first byte (up to the 0.2 s timeout), then take whatever else has arrived:
                # read(256) would sit on a short frame until 256 bytes or the timeout (up to 200 ms late)
                chunk = self.ser.read(1)
                if chunk:
                    waiting = self.ser.in_waiting
                    if waiting:
                        chunk += self.ser.read(waiting)
            except Exception as e:
                log.error("serial read failed: %s", e)
                self.events.put(("serial_error", str(e)))
                return
            if not chunk:
                if self._pending_rx is not None:  # no RxMeta coming
                    self._flush_rx()
                continue
            for b in chunk:
                if b == FEND:
                    if in_frame and buf:
                        self._on_frame(bytes(buf))
                    buf.clear()
                    in_frame = True
                    esc = False
                elif not in_frame:
                    continue
                elif esc:
                    buf.append(FEND if b == TFEND else FESC if b == TFESC else b)
                    esc = False
                elif b == FESC:
                    esc = True
                else:
                    buf.append(b)
                    if len(buf) > 600:
                        buf.clear()
                        in_frame = False




# ============================================================================
# Helpers
# ============================================================================

def airtime_ms(rc, length):
    """LoRa time on air of a packet of `length` bytes with a radio's configured settings (explicit header, CRC on)."""
    bw, sf, cr = float(rc["bw_khz"]) * 1000.0, int(rc["sf"]), int(rc["cr"])
    ts = (1 << sf) / bw
    de = 1 if ts > 0.016 else 0
    n = 8 + max(math.ceil((8 * length - 4 * sf + 28 + 16) / (4 * (sf - 2 * de))) * cr, 0)
    return int((16 + 4.25 + n) * ts * 1000)


def utf8_cut(b, n):
    """At most n bytes of UTF-8, never ending mid-character."""
    b = b[:n]
    while b:
        try:
            b.decode()
            return b
        except UnicodeDecodeError:
            b = b[:-1]
    return b


def make_advert(identity, name, lat, lon):
    """A signed repeater advert: type, position (only when set), name (cut to fit)."""
    flags = ADV_TYPE_REPEATER
    body = b""
    if lat is not None and lon is not None:
        flags |= ADV_LATLON_MASK
        body += struct.pack("<ii", int(round(lat * 1e6)), int(round(lon * 1e6)))
    name = utf8_cut(str(name).encode(), MAX_ADVERT_DATA_SIZE - 1 - len(body))
    if name:
        flags |= ADV_NAME_MASK
    app_data = bytes([flags]) + body + name
    ts = struct.pack("<I", now_s())
    sig = identity.sign(identity.pub_key + ts + app_data)
    return Packet(PT_ADVERT, identity.pub_key + ts + sig + app_data)


def advert_info(payload):
    """(advert type, name) from an advert's app data, or (None, None)."""
    a = payload[100:]
    if not a:
        return None, None
    flags, i = a[0], 1
    if flags & ADV_LATLON_MASK:
        i += 8
    if flags & 0x20:
        i += 2
    if flags & 0x40:
        i += 2
    name = None
    if flags & ADV_NAME_MASK:
        name = a[i:].split(b"\0", 1)[0].decode("utf-8", "replace")
    return flags & 0x0F, name


def generate_private_key():
    """A new MeshCore-style 64-byte private key (clamped SHA-512 of a random seed), as hex."""
    h = bytearray(hashlib.sha512(os.urandom(32)).digest())
    h[0] &= 248; h[31] &= 127; h[31] |= 64
    return bytes(h).hex()


def hash_web_password(pw):
    salt = os.urandom(16)
    n = 100000
    return "pbkdf2_sha256$%d$%s$%s" % (n, salt.hex(), hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, n).hex())


def check_web_password(pw, stored):
    try:
        algo, n, salt, h = str(stored).split("$")
        if algo != "pbkdf2_sha256":
            return False
        got = hashlib.pbkdf2_hmac("sha256", str(pw).encode(), bytes.fromhex(salt), int(n)).hex()
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, h)


def channel_secret(name):
    """'public' (the well-known key) or '#name' (first 16 bytes of SHA-256 of the name) -> 16-byte key, or None."""
    n = str(name).strip()
    if n.lower() == "public":
        return PUBLIC_CHANNEL_KEY
    if n.startswith("#") and len(n) > 1:
        return hashlib.sha256(n.encode()).digest()[:16]
    return None


# ============================================================================
# Configuration (config.json; the repo ships config.example.json)
# ============================================================================

LORA_BWS = (7.8, 10.4, 15.6, 20.8, 31.25, 41.7, 62.5, 125.0, 250.0, 500.0)
LOOP_MODES = ("off", "minimal", "moderate", "strict")
FILTER_MODES = ("only", "except")

DEFAULT_RADIO = {
    "enabled": True,
    "serial": "/dev/ttyACM0",
    "baud": 115200,
    "freq_mhz": 910.525,
    "bw_khz": 62.5,
    "sf": 7,
    "cr": 5,                    # coding rate 4/5 .. 4/8
    "tx_power_dbm": None,       # None = leave the modem's default
    "hash_mode": 0,             # 0/1/2 = 1/2/3-byte path ids in adverts this repeater sends
    "repeat_same": True,        # packets heard on this radio are repeated on this radio
    "repeat_cross": False,      # packets heard on this radio are repeated on the other radio
    "advert": True,             # this radio sends the repeater's adverts
    "airtime_pct": 100,         # relays may use at most this share of this radio's airtime
    "kiss_txdelay": 1,          # KISS TXDELAY (x10 ms)
    "kiss_persistence": 128,    # KISS CSMA persistence 0-255
    "kiss_slottime": 5,         # KISS slot time (x10 ms)
}

DEFAULT_CONFIG = {
    "listen_address": "0.0.0.0",
    "listen_port": 8090,
    "web_password": "",         # written back as a hash on start; empty = admin panel disabled
    "data_dir": "./data",
    "log_level": "info",
    "private_key": "",          # 64-byte MeshCore private key (hex); generated on first start if empty
    "name": "MCX Repeater",
    "lat": None,
    "lon": None,
    "advert_interval_min": 60,  # zero-hop advert (0 = off)
    "flood_advert_interval_h": 12,
    "relay_enabled": True,      # kill switch: off = adverts only, nothing relayed
    "max_flood_hops": 64,
    "loop_detect": "minimal",
    "radio1": dict(DEFAULT_RADIO),
    "radio2": dict(DEFAULT_RADIO, enabled=False, serial="/dev/ttyACM1", freq_mhz=907.875),
    "regions": {"mode": "except", "list": [], "relay_unscoped": True},
    "packet_types": {"mode": "except", "list": []},
    "blacklist": {"prefixes": [], "channel_names": []},
}

RADIOS = ("radio1", "radio2")


def _merge(base, over):
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _bool(v, what):
    if not isinstance(v, bool):
        raise ValueError("%s: true or false" % what)
    return v


def _int(v, lo, hi, what):
    if isinstance(v, bool):
        raise ValueError("%s: a number" % what)
    try:
        f = float(v)
    except (TypeError, ValueError):
        raise ValueError("%s: a number" % what)
    if f != int(f) or not lo <= f <= hi:
        raise ValueError("%s: a whole number from %s to %s" % (what, lo, hi))
    return int(f)


def _float(v, lo, hi, what):
    if isinstance(v, bool):
        raise ValueError("%s: a number" % what)
    try:
        f = float(v)
    except (TypeError, ValueError):
        raise ValueError("%s: a number" % what)
    if not lo <= f <= hi or f != f:
        raise ValueError("%s: from %s to %s" % (what, lo, hi))
    return f


def _opt_float(v, lo, hi, what):
    if v is None or (isinstance(v, str) and not v.strip()):
        return None
    return _float(v, lo, hi, what)


def normalise_radio(r, label):
    o = dict(r)
    o["enabled"] = _bool(o["enabled"], label + " enabled")
    o["serial"] = str(o["serial"]).strip()
    if not o["serial"]:
        raise ValueError(label + " serial port: required")
    if "/" not in o["serial"]:                              # a bare name: ttyACM0, or a /dev/serial/by-id/ entry
        by_id = os.path.join("/dev/serial/by-id", o["serial"])
        o["serial"] = by_id if os.path.exists(by_id) or not o["serial"].startswith("tty") else "/dev/" + o["serial"]
    o["baud"] = _int(o["baud"], 1200, 4000000, label + " baud")
    o["freq_mhz"] = round(_float(o["freq_mhz"], 137, 1020, label + " frequency (MHz)"), 6)
    bw = _float(o["bw_khz"], 7, 500, label + " bandwidth (kHz)")
    if not any(abs(bw - b) < 0.05 for b in LORA_BWS):
        raise ValueError(label + " bandwidth: one of " + ", ".join("%g" % b for b in LORA_BWS) + " kHz")
    o["bw_khz"] = bw
    o["sf"] = _int(o["sf"], 5, 12, label + " spreading factor")
    o["cr"] = _int(o["cr"], 5, 8, label + " coding rate (5-8 for 4/5-4/8)")
    p = o["tx_power_dbm"]
    o["tx_power_dbm"] = None if p is None or (isinstance(p, str) and not p.strip()) else _int(p, -9, 30, label + " TX power (dBm)")
    o["hash_mode"] = _int(o["hash_mode"], 0, 2, label + " hash mode")
    for k in ("repeat_same", "repeat_cross", "advert"):
        o[k] = _bool(o[k], "%s %s" % (label, k))
    o["airtime_pct"] = _int(o["airtime_pct"], 1, 100, label + " airtime cap (%)")
    for k in ("kiss_txdelay", "kiss_persistence", "kiss_slottime"):
        o[k] = _int(o[k], 0, 255, "%s %s" % (label, k))
    return {k: o[k] for k in DEFAULT_RADIO}


REGION_RE = re.compile(r"^[A-Za-z0-9-]{1,30}$")
PREFIX_RE = re.compile(r"^[0-9a-f]{1,64}\*?$")


def normalise(cfg):
    """Validate a whole config (defaults filled in). Returns a clean copy; raises ValueError with a readable message."""
    c = _merge(DEFAULT_CONFIG, cfg)
    c = {k: c[k] for k in DEFAULT_CONFIG}
    c["listen_address"] = str(c["listen_address"]).strip() or "0.0.0.0"
    c["listen_port"] = _int(c["listen_port"], 1, 65535, "listen port")
    c["web_password"] = str(c["web_password"] or "")
    c["data_dir"] = str(c["data_dir"] or "./data")
    c["log_level"] = str(c["log_level"] or "info").lower()
    pk = str(c["private_key"] or "").strip().lower()
    if pk:
        if not re.match(r"^[0-9a-f]+$", pk) or len(pk) not in (64, 128):
            raise ValueError("private key: 64 or 128 hex characters")
    c["private_key"] = pk
    name = str(c["name"] or "").strip()
    if not name:
        raise ValueError("name: required")
    if len(name.encode()) > 31:
        raise ValueError("name: at most 31 bytes")
    c["name"] = name
    c["lat"] = _opt_float(c["lat"], -90, 90, "latitude")
    c["lon"] = _opt_float(c["lon"], -180, 180, "longitude")
    if (c["lat"] is None) != (c["lon"] is None):
        raise ValueError("location: give both latitude and longitude, or neither")
    if c["lat"] is not None and len(c["name"].encode()) > 23:
        raise ValueError("name: at most 23 bytes when a location is set (adverts have 32 bytes of data)")
    c["advert_interval_min"] = _int(c["advert_interval_min"], 0, 1440, "zero-hop advert interval (minutes)")
    c["flood_advert_interval_h"] = _int(c["flood_advert_interval_h"], 0, 168, "flood advert interval (hours)")
    c["relay_enabled"] = _bool(c["relay_enabled"], "relay enabled")
    c["max_flood_hops"] = _int(c["max_flood_hops"], 1, 64, "max flood hops")
    if c["loop_detect"] not in LOOP_MODES:
        raise ValueError("loop detection: one of " + ", ".join(LOOP_MODES))
    for r in RADIOS:
        if not isinstance(c[r], dict):
            raise ValueError(r + ": settings expected")
        c[r] = normalise_radio(_merge(DEFAULT_RADIO, c[r]), r)

    rg = c["regions"]
    if rg.get("mode") not in FILTER_MODES:
        raise ValueError("regions mode: only or except")
    names = []
    for n in rg.get("list") or []:
        n = str(n).strip().lstrip("#")
        if not n:
            continue
        if not REGION_RE.match(n):
            raise ValueError("region %r: letters, digits and - only (private $ regions aren't supported)" % n)
        if n not in names:
            names.append(n)
    c["regions"] = {"mode": rg["mode"], "list": names, "relay_unscoped": _bool(rg.get("relay_unscoped", True), "relay unscoped floods")}

    pt = c["packet_types"]
    if pt.get("mode") not in FILTER_MODES:
        raise ValueError("packet types mode: only or except")
    types = []
    for t in pt.get("list") or []:
        t = str(t).strip().upper()
        if t not in PT_BY_NAME:
            raise ValueError("packet type %r: one of %s" % (t, ", ".join(PT_NAMES.values())))
        if t not in types:
            types.append(t)
    c["packet_types"] = {"mode": pt["mode"], "list": types}

    bl = c["blacklist"]
    prefixes = []
    for p in bl.get("prefixes") or []:
        p = str(p).strip().lower().replace(" ", "")
        if not p:
            continue
        if not PREFIX_RE.match(p):
            raise ValueError("blacklist %r: hex digits, optionally ending in * (e.g. 5b* or 5b98*)" % p)
        if not p.endswith("*") and len(p) < 64:
            p += "*"
        if p not in prefixes:
            prefixes.append(p)
    chans = []
    for e in bl.get("channel_names") or []:
        if not isinstance(e, dict):
            raise ValueError("channel blacklist: {channel, name} entries expected")
        ch, nm = str(e.get("channel", "")).strip(), str(e.get("name", "")).strip()
        if ch.lower() == "public":
            ch = "public"
        elif ch and not ch.startswith("#"):
            ch = "#" + ch
        if channel_secret(ch) is None:
            raise ValueError("channel %r: 'public' or a #hashtag channel" % ch)
        if not nm:
            raise ValueError("channel blacklist: a name is required")
        ent = {"channel": ch, "name": nm}
        if ent not in chans:
            chans.append(ent)
    c["blacklist"] = {"prefixes": prefixes, "channel_names": chans}
    return c


SETTABLE = ("name", "lat", "lon", "advert_interval_min", "flood_advert_interval_h", "relay_enabled", "max_flood_hops",
            "loop_detect", "radio1", "radio2", "regions", "packet_types", "blacklist")


def apply_settings(cfg, body):
    """Web UI change -> new validated config. Only SETTABLE keys; the password, key and listen address aren't here."""
    if not isinstance(body, dict) or not body:
        raise ValueError("no settings given")
    bad = [k for k in body if k not in SETTABLE]
    if bad:
        raise ValueError("unknown setting(s): " + ", ".join(sorted(bad)))
    new = copy.deepcopy(cfg)
    for k, v in body.items():
        if k in ("regions", "packet_types", "blacklist"):
            new[k] = _merge(new[k], v) if isinstance(v, dict) else v      # lists replace, not merge
            if isinstance(v, dict):
                for lk in ("list", "prefixes", "channel_names"):
                    if lk in v:
                        new[k][lk] = copy.deepcopy(v[lk])
        elif k in RADIOS:
            if not isinstance(v, dict):
                raise ValueError(k + ": settings expected")
            new[k] = dict(new[k], **v)
        else:
            new[k] = v
    return normalise(new)


def load_config(path):
    with open(path) as f:
        raw = json.load(f)
    return normalise(raw)


def save_config(path, cfg):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def public_settings(cfg):
    """What the admin panel shows: everything but the password hash and the private key."""
    return {k: v for k, v in cfg.items() if k not in ("web_password", "private_key")}


# ============================================================================
# Radio: a KISS modem and its transmitter thread
# ============================================================================

class Radio:
    """One radio. Its transmitter thread owns the modem: opens and pings it, pushes the configured radio settings
    (again whenever they change or the modem reboots), and sends relays when they're due, one at a time, waiting
    for TxDone. Channel access (listen before talk) is the modem's own KISS CSMA."""

    def __init__(self, app, index, modem_factory=None):
        self.app, self.idx, self.name = app, index, RADIOS[index]
        self.modem_factory = modem_factory or KissModem
        self.modem = None
        self.port = None                                    # (serial, baud) the modem was opened with
        self.applied = None                                 # radio settings last pushed
        self.reported = None                                # (freq Hz, bw Hz, sf, cr) as the modem reports them
        self.status = "starting"
        self.lost = False
        self.lost_reason = ""
        self.heap = []
        self.seq = itertools.count()
        self.cond = threading.Condition()
        self.txdone = threading.Event()
        self.txdone_ok = True
        self.txbusy = False
        self.budget_ms, self.budget_t = None, time.monotonic()
        self.recent_tx = collections.deque()                # (monotonic, airtime ms), last 10 minutes
        self.stats = dict(tx=0, tx_airtime_ms=0, tx_errors=0, txbusy=0, drop_queue=0, drop_airtime=0)
        self.next_check = 0.0

    cfg = property(lambda s: s.app.cfg[s.name])

    # ---------------------------------------------------------------- modem events (reader thread)

    def put(self, ev):
        kind = ev[0]
        if kind == "rx":
            self.app.rxq.put(("rx", self.idx, ev[1], ev[2], ev[3]))
        elif kind == "txdone":
            self.txdone_ok = bool(ev[1])
            self.txdone.set()
        elif kind == "txbusy":
            self.txbusy = True
            self.txdone.set()
        elif kind == "serial_error":
            self.lost = True
            self.lost_reason = ev[1] if len(ev) > 1 else ""
            self.wake()

    def wake(self):
        with self.cond:
            self.cond.notify_all()

    # ---------------------------------------------------------------- queue (evaluator thread)

    def airtime_ok(self, at, pct):
        """Relays share an airtime budget: refills at airtime_pct of the time, holds a minute's worth."""
        if pct >= 100:
            return True
        now = time.monotonic()
        cap = 60000.0 * pct / 100.0
        if self.budget_ms is None:
            self.budget_ms = cap
        self.budget_ms = min(cap, self.budget_ms + (now - self.budget_t) * 1000.0 * pct / 100.0)
        self.budget_t = now
        if self.budget_ms < at:
            return False
        self.budget_ms -= at
        return True

    def tx_delay(self, pkt, factor):
        """Firmware getRetransmitDelay / getDirectRetransmitDelay: random 0..5 x (airtime x factor), in seconds."""
        t = int(airtime_ms(self.cfg, path_bytes(pkt.path_len) + len(pkt.payload) + 2) * factor)
        return random.randint(0, 5 * t) / 1000.0 if t > 0 else 0.0

    def enqueue(self, pkt, prio, factor=None, delay=0.0, own=False):
        """Queue a packet. Relays (own=False) are capped by queue size and airtime; returns a drop reason or None."""
        rc = self.cfg
        if not rc["enabled"]:
            return "radio off"
        raw = pkt.encode()
        if factor is not None:
            delay = self.tx_delay(pkt, factor)
        with self.cond:
            if not own:
                if sum(1 for e in self.heap if not e[4]) >= RPT_MAX_QUEUED:
                    self.stats["drop_queue"] += 1
                    return "queue full"
                if not self.airtime_ok(airtime_ms(rc, len(raw)), rc["airtime_pct"]):
                    self.stats["drop_airtime"] += 1
                    return "airtime cap"
            heapq.heappush(self.heap, (time.monotonic() + delay, prio, next(self.seq), raw, own, 0))
            self.cond.notify_all()
        return None

    def queued(self):
        with self.cond:
            return len(self.heap)

    def purge(self):
        with self.cond:
            n = len(self.heap)
            self.heap.clear()
        return n

    # ---------------------------------------------------------------- transmitter thread

    def radio_params(self, rc):
        return (int(round(rc["freq_mhz"] * 1e6)), int(round(rc["bw_khz"] * 1e3)), rc["sf"], rc["cr"])

    def close(self):
        if self.modem is not None:
            self.modem.close()
        self.modem, self.port, self.applied, self.reported = None, None, None, None

    def connect(self, rc):
        self.close()
        self.lost = False
        try:
            m = self.modem_factory(rc["serial"], rc["baud"], self)
        except Exception as e:
            self.status = "can't open %s: %s" % (rc["serial"], e)
            return False
        for _ in range(10):                                 # give a modem that just reset time to boot
            if m.command(0x17, timeout=1.5) is not None:
                break
            if self.app.stopping or self.lost:
                break
        else:
            m.close()
            self.status = "no KISS modem answering on %s" % rc["serial"]
            return False
        if self.lost:
            m.close()
            self.status = "lost %s: %s" % (rc["serial"], self.lost_reason or "serial error")
            if "readiness to read" in self.lost_reason:
                self.status += " (another program is using this port, e.g. ModemManager or another repeater)"
            return False
        m.command(0x19, b"\x01")                            # RxMeta (SNR/RSSI) on
        self.modem, self.port = m, (rc["serial"], rc["baud"])
        log.info("%s: KISS modem on %s", self.name, rc["serial"])
        return True

    def configure(self, rc):
        """Push the radio settings (the modem reverts to compiled defaults on every reboot)."""
        m = self.modem
        m.set_param(0x01, rc["kiss_txdelay"])
        m.set_param(0x02, rc["kiss_persistence"])
        m.set_param(0x03, rc["kiss_slottime"])
        want = self.radio_params(rc)
        ok = m.command(0x09, struct.pack("<IIBB", *want), timeout=3) is not None
        if rc["tx_power_dbm"] is not None:
            m.command(0x0A, bytes([rc["tx_power_dbm"] & 0xFF]), timeout=3)
        r = m.command(0x0B)
        self.reported = struct.unpack("<IIBB", r[:10]) if r and len(r) >= 10 else None
        self.applied = (want, rc["tx_power_dbm"], rc["kiss_txdelay"], rc["kiss_persistence"], rc["kiss_slottime"])
        if not ok or self.reported != want:
            self.status = "modem did not accept the radio settings (reports %s)" % (self.reported,)
            log.error("%s: modem did not accept radio settings %s (reports %s)", self.name, want, self.reported)
        else:
            self.status = "ok"
            log.info("%s: %.3f MHz, BW %g kHz, SF%d, CR4/%d", self.name, rc["freq_mhz"], rc["bw_khz"], rc["sf"], rc["cr"])
        self.next_check = time.monotonic() + 60

    def check_reverted(self, rc):
        """Every minute: a modem that rebooted reverts to its defaults; push the settings again."""
        r = self.modem.command(0x0B)
        self.next_check = time.monotonic() + 60
        if r and len(r) >= 10 and struct.unpack("<IIBB", r[:10]) != self.radio_params(rc):
            log.warning("%s: modem radio settings reverted (modem rebooted?) - re-applying", self.name)
            self.applied = None

    def run(self):
        while not self.app.stopping:
            try:
                self.step()
            except Exception:
                log.exception("%s transmitter", self.name)
                self.lost = True
                time.sleep(1)
        self.close()

    def step(self):
        rc = self.cfg
        if not rc["enabled"]:
            if self.modem is not None:
                self.close()
                self.purge()
            self.status = "disabled"
            with self.cond:
                self.cond.wait(1.0)
            return
        if self.modem is None or self.lost or self.port != (rc["serial"], rc["baud"]):
            before = self.status
            if not self.connect(rc):
                if self.status != before:
                    log.warning("%s: %s - retrying every 5 s", self.name, self.status)
                with self.cond:
                    self.cond.wait(5.0)
                return
        if self.applied != (self.radio_params(rc), rc["tx_power_dbm"], rc["kiss_txdelay"], rc["kiss_persistence"],
                            rc["kiss_slottime"]):
            self.configure(rc)
        elif time.monotonic() >= self.next_check:
            self.check_reverted(rc)
            return
        with self.cond:
            now = time.monotonic()
            due = [e for e in self.heap if e[0] <= now]
            if not due:
                wait = min([e[0] for e in self.heap] + [now + 1.0]) - now
                self.cond.wait(max(0.01, wait))
                return
            best = min(due, key=lambda e: (e[1], e[2]))
            self.heap.remove(best)
            heapq.heapify(self.heap)
        self.transmit(best, rc)

    def transmit(self, e, rc):
        raw = e[3]
        at = airtime_ms(rc, len(raw))
        self.txdone.clear()
        self.txbusy = False
        self.modem.send_packet(raw)
        got = self.txdone.wait(at / 1000.0 + 3.0)
        if self.txbusy:                                     # the modem refused: channel busy / still sending
            self.stats["txbusy"] += 1
            if e[5] < TXBUSY_RETRIES:
                with self.cond:
                    heapq.heappush(self.heap, (time.monotonic() + random.uniform(0.1, 0.5), e[1], e[2], raw, e[4], e[5] + 1))
            return
        if not got or not self.txdone_ok:
            self.stats["tx_errors"] += 1
        self.stats["tx"] += 1
        self.stats["tx_airtime_ms"] += at
        now = time.monotonic()
        self.recent_tx.append((now, at))
        while self.recent_tx and now - self.recent_tx[0][0] > 600:
            self.recent_tx.popleft()

    def airtime_used(self):
        """TX share of the last 10 minutes (or since start), %."""
        now = time.monotonic()
        span = max(60.0, min(600.0, now - self.app.boot))
        return round(100.0 * sum(a for t, a in list(self.recent_tx) if now - t <= 600) / (span * 1000.0), 1)


# ============================================================================
# The repeater: evaluator thread, adverts, web state
# ============================================================================

DROP_REASONS = ("duplicate", "not for us", "zero hop", "relay off", "packet type", "blacklist", "region", "hops",
                "loop", "repeat off", "bad signature", "malformed", "queue full", "airtime cap", "own")


class Repeater:
    def __init__(self, cfg, cfg_path=None, modem_factory=None):
        self.cfg = cfg                                      # replaced (never mutated) when settings change
        self.cfg_path = cfg_path
        self.cfg_lock = threading.Lock()
        self.ident = RepeaterIdentity(bytes.fromhex(cfg["private_key"]))
        self.rxq = queue.Queue()
        self.stopping = False
        self.boot = time.monotonic()
        self.started = now_s()                              # the firmware's discovery_mod_timestamp
        self.radios = [Radio(self, i, modem_factory) for i in range(len(RADIOS))]
        self.seen = {}                                      # packet hash -> None (insertion ordered)
        self.neigh = {}                                     # id hex (1-3 bytes, or a full key) -> neighbour
        self.names = collections.OrderedDict()              # public key hex -> advertised name
        self.log = collections.deque(maxlen=LOG_MAX)
        self.stats = collections.Counter()
        self.rx = [collections.Counter() for _ in RADIOS]
        self.totals = collections.Counter()                 # earlier runs (data_dir/stats.json)
        self.disc_window = [0, 0]
        self.next_zero_advert = time.monotonic() + 8
        self.next_flood_advert = time.monotonic() + 20
        self.next_snapshot = 0.0
        self.next_save = time.monotonic() + 60
        self.snapshot = {}
        self._chan_cache = (None, [])
        self._region_cache = (None, [])
        self.load_stats()

    # ---------------------------------------------------------------- threads

    def start(self):
        for r in self.radios:
            threading.Thread(target=r.run, name="tx-" + r.name, daemon=True).start()
        threading.Thread(target=self.run, name="evaluator", daemon=True).start()

    def stop(self):
        self.stopping = True
        for r in self.radios:
            r.wake()
        self.save_stats()

    def run(self):
        while not self.stopping:
            try:
                ev = self.rxq.get(timeout=0.25)
            except queue.Empty:
                ev = None
            try:
                if ev is not None:
                    self.on_event(ev)
                self.periodic()
            except Exception:
                log.exception("evaluator")

    def on_event(self, ev):
        if ev[0] == "rx":
            self.on_rx(ev[1], ev[2], ev[3], ev[4])
        elif ev[0] == "advert":
            self.send_advert(ev[1])
        elif ev[0] == "advert_soon":
            self.next_zero_advert = min(self.next_zero_advert, time.monotonic() + 3)

    def periodic(self):
        now = time.monotonic()
        c = self.cfg
        if c["advert_interval_min"] and now >= self.next_zero_advert:
            self.send_advert(False)
            self.next_zero_advert = now + c["advert_interval_min"] * 60
        elif not c["advert_interval_min"]:
            self.next_zero_advert = max(self.next_zero_advert, now + 60)
        if c["flood_advert_interval_h"] and now >= self.next_flood_advert:
            self.send_advert(True)
            self.next_flood_advert = now + c["flood_advert_interval_h"] * 3600
        if now >= self.next_snapshot:
            self.snapshot = self.make_snapshot()            # swapped in whole: the web threads only read it
            self.next_snapshot = now + 1.0
        if now >= self.next_save:
            self.save_stats()
            self.next_save = now + 60

    # ---------------------------------------------------------------- stats persistence

    def stats_path(self):
        if not self.cfg_path:
            return None
        return os.path.join(os.path.dirname(os.path.abspath(self.cfg_path)), self.cfg["data_dir"], "stats.json")

    def load_stats(self):
        p = self.stats_path()
        if not p or not os.path.exists(p):
            return
        try:
            with open(p) as f:
                self.totals = collections.Counter({k: int(v) for k, v in json.load(f).get("totals", {}).items()})
        except (OSError, ValueError, AttributeError) as e:
            log.warning("could not read %s: %s", p, e)

    def save_stats(self):
        p = self.stats_path()
        if not p:
            return
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            tmp = p + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"totals": dict(self.totals + self.stats), "saved": now_s()}, f)
            os.replace(tmp, p)
        except OSError as e:
            log.warning("could not save %s: %s", p, e)

    # ---------------------------------------------------------------- duplicates

    def was_seen(self, pkt):
        return pkt.packet_hash() in self.seen

    def seen_mark(self, pkt):
        self.seen[pkt.packet_hash()] = None
        while len(self.seen) > SEEN_MAX:
            self.seen.pop(next(iter(self.seen)))

    # ---------------------------------------------------------------- neighbours

    def note_neighbour(self, idb, radio, snr, name=None):
        me = self.ident.pub_key
        if me[:len(idb)] == idb:
            return                                          # our own id (heard on the other radio)
        now = time.time()
        key = idb.hex()
        e = self.neigh.get(key)
        if e is None:
            if len(self.neigh) >= NEIGHBOURS_MAX:
                del self.neigh[min(self.neigh, key=lambda k: self.neigh[k]["last"])]
            e = self.neigh[key] = dict(id=key, radios={}, snr={}, name=None, last=now)
        e["radios"][radio] = now
        e["snr"][radio] = snr
        e["last"] = now
        if name:
            e["name"] = name

    def neighbour_radios(self, idb):
        """Radios a neighbour with this id (1-3 byte prefix) was heard on recently. Empty = unknown."""
        h, now, out = idb.hex(), time.time(), set()
        for key, e in self.neigh.items():
            if key.startswith(h) or h.startswith(key):
                out.update(r for r, ts in e["radios"].items() if now - ts < NEIGHBOUR_TTL_S)
        return out

    def learn(self, radio, pkt):
        """Neighbours: the last hop of a flood is the repeater we just heard; a zero-hop advert is its sender."""
        if pkt.is_flood and pkt.hop_count:
            sz, n = pkt.hash_size, pkt.hop_count
            self.note_neighbour(pkt.path[(n - 1) * sz:n * sz], radio, pkt.snr)
        if pkt.ptype == PT_ADVERT and len(pkt.payload) >= 101:
            pub = pkt.payload[:PUB_KEY_SIZE]
            _, name = advert_info(pkt.payload)
            if name:
                self.names[pub.hex()] = name
                self.names.move_to_end(pub.hex())
                while len(self.names) > 2000:
                    self.names.popitem(last=False)
            if pkt.hop_count == 0 and pub != self.ident.pub_key:
                self.note_neighbour(pub, radio, pkt.snr, name)

    def name_for(self, idhex):
        for pub in reversed(self.names):
            if pub.startswith(idhex):
                return self.names[pub]
        return None

    # ---------------------------------------------------------------- policy

    def regions(self, c):
        names = tuple(c["regions"]["list"])
        if self._region_cache[0] != names:
            self._region_cache = (names, [(n, transport_key(n)) for n in names])
        return self._region_cache[1]

    def scope_ok(self, pkt, c):
        """Unscoped floods: the relay_unscoped checkbox. A scoped flood carries a code computed from its region's
        key (RegionMap::findMatch): "only" relays listed regions, "except" all but them. Code 0 means 'send to
        nowhere' and FFFF is reserved: never relayed."""
        if pkt.route_type != ROUTE_TRANSPORT_FLOOD:
            return c["regions"]["relay_unscoped"]
        code = pkt.transport_codes[0]
        if code in (0, 0xFFFF):
            return False
        match = any(transport_code(key, pkt) == code for _, key in self.regions(c))
        return match if c["regions"]["mode"] == "only" else not match

    def looped(self, pkt, c):
        """MyMesh::isLooped: this repeater already appears in the path too often (per path id size)."""
        maxes = RPT_LOOP_MAX.get(c["loop_detect"])
        if not maxes:
            return False
        sz, k = pkt.hash_size, pkt.hop_count
        mine = self.ident.pub_key[:sz]
        n = sum(1 for i in range(k) if pkt.path[i * sz:(i + 1) * sz] == mine)
        return n >= maxes.get(sz, 1)

    def channel_blocks(self, c):
        ents = tuple((e["channel"], e["name"]) for e in c["blacklist"]["channel_names"])
        if self._chan_cache[0] != ents:
            out = []
            for ch, nm in ents:
                k = channel_secret(ch)
                out.append((hashlib.sha256(k).digest()[0], k + bytes(16), nm.lower(), ch))
            self._chan_cache = (ents, out)
        return self._chan_cache[1]

    def source(self, pkt):
        """(full source key hex or None, 1-byte source hash hex or None)."""
        p, t = pkt.payload, pkt.ptype
        if t == PT_ADVERT and len(p) >= PUB_KEY_SIZE:
            return p[:PUB_KEY_SIZE].hex(), None
        if t == PT_ANON_REQ and len(p) >= 1 + PUB_KEY_SIZE:
            return p[1:1 + PUB_KEY_SIZE].hex(), None
        if t in (PT_REQ, PT_RESPONSE, PT_TXT_MSG, PT_PATH) and len(p) >= 2:
            return None, p[1:2].hex()
        return None, None

    def blacklisted(self, pkt, c):
        """The matching blacklist entry, or None. Full keys (adverts, logins) match any prefix; DMs, requests,
        responses and paths carry a 1-byte source hash, matched only by 1-byte (or shorter) prefixes."""
        full, byte = self.source(pkt)
        for pat in c["blacklist"]["prefixes"]:
            pre = pat.rstrip("*")
            if full is not None and full.startswith(pre):
                return pat
            if byte is not None and len(pre) <= 2 and byte.startswith(pre):
                return pat
        if pkt.ptype == PT_GRP_TXT and len(pkt.payload) > 3:
            for h, key, nm, ch in self.channel_blocks(c):
                if h != pkt.payload[0]:
                    continue
                data = mac_then_decrypt(key, pkt.payload[1:])
                if data is None or len(data) < 6:
                    continue
                sender = data[5:].split(b"\0", 1)[0].split(b": ", 1)[0].decode("utf-8", "replace").strip().lower()
                if sender == nm:
                    return "%s in %s" % (nm, ch)
        return None

    def filters(self, pkt, c):
        """Kill switch, packet types, blacklist. Returns (reason, detail) or None."""
        if not c["relay_enabled"]:
            return "relay off", ""
        name = PT_NAMES.get(pkt.ptype, "UNKNOWN")
        listed = name in c["packet_types"]["list"]
        if listed != (c["packet_types"]["mode"] == "only"):
            return "packet type", name
        b = self.blacklisted(pkt, c)
        if b:
            return "blacklist", b
        return None

    def targets(self, radio, c):
        """Radios a packet heard on `radio` may be repeated on: this one (same frequency) and/or the other (cross)."""
        rc = c[RADIOS[radio]]
        out = []
        if rc["repeat_same"]:
            out.append(radio)
        if rc["repeat_cross"]:
            out += [i for i, n in enumerate(RADIOS) if i != radio and c[n]["enabled"]]
        return out

    def direct_targets(self, radio, next_id, c):
        """A direct packet goes out on the radio its next hop was heard on; unknown -> every allowed radio."""
        allowed = self.targets(radio, c)
        if not next_id or not allowed:
            return allowed
        known = self.neighbour_radios(next_id)
        if not known:
            return allowed
        return [r for r in allowed if r in known]

    # ---------------------------------------------------------------- receive

    def on_rx(self, radio, raw, snr, rssi):
        self.stats["rx"] += 1
        self.rx[radio]["rx"] += 1
        rc = self.cfg[RADIOS[radio]]
        self.rx[radio]["rx_airtime_ms"] += airtime_ms(rc, len(raw))
        entry = dict(t=time.time(), radio=radio + 1, snr=snr, rssi=rssi, len=len(raw))
        pkt = Packet.parse(raw)
        if pkt is None:
            entry.update(type="?", route="?", hops=None, result="dropped", reason="malformed")
            self.count_drop("malformed")
            self.log.append(entry)
            return
        pkt.snr, pkt.rssi = snr, rssi
        full, byte = self.source(pkt)
        entry.update(type=PT_NAMES.get(pkt.ptype, "0x%X" % pkt.ptype), route=ROUTE_NAMES[pkt.route_type],
                     hops=pkt.hop_count, src=(full[:8] if full else byte or ""))
        self.learn(radio, pkt)
        try:
            actions, reason, detail = self.evaluate(radio, pkt, self.cfg)
        except (IndexError, struct.error):
            actions, reason, detail = [], "malformed", ""
        sent, why = [], None
        for target, fwd, prio, factor in actions:
            err = self.radios[target].enqueue(fwd, prio, factor)
            if err is None:
                sent.append(target)
            else:
                why = err
        if sent:
            kind = "relayed_" + ("flood" if pkt.is_flood else "trace" if pkt.ptype == PT_TRACE
                                 else "discovery" if pkt.ptype == PT_CONTROL else "ack" if pkt.ptype == PT_ACK else "direct")
            self.stats["relayed"] += 1
            self.stats[kind] += 1
            for t in sent:
                self.rx[t]["relays_out"] += 1
            entry.update(result="relayed" if pkt.ptype != PT_CONTROL else "answered",
                         reason="on " + " + ".join(RADIOS[t] for t in sent))
        else:
            reason = why if actions else reason
            self.count_drop(reason)
            entry.update(result="dropped", reason=reason + (" (%s)" % detail if detail else ""))
        self.log.append(entry)

    def count_drop(self, reason):
        self.stats["dropped"] += 1
        self.stats["drop_" + reason.replace(" ", "_")] += 1

    def evaluate(self, radio, pkt, c):
        """-> ([(radio, packet, priority, delay factor)], drop reason, detail)."""
        t = pkt.ptype
        if t == PT_ADVERT and pkt.payload[:PUB_KEY_SIZE] == self.ident.pub_key:
            return [], "own", ""
        if pkt.is_flood:
            return self.eval_flood(radio, pkt, c)
        if t == PT_TRACE:
            return self.eval_trace(radio, pkt, c)
        if t == PT_CONTROL and pkt.payload[:1] and pkt.payload[0] & 0x80:
            if pkt.hop_count == 0:
                return self.eval_control(radio, pkt, c)
            return [], "zero hop", ""
        if pkt.hop_count == 0:
            return [], "zero hop", ""
        return self.eval_direct(radio, pkt, c)

    def eval_flood(self, radio, pkt, c):
        """Mesh.cpp routeRecvPacket + MyMesh::allowPacketForward for floods."""
        p, t = pkt.payload, pkt.ptype
        if t == PT_ACK:
            ok = len(p) >= 4
        elif t in (PT_PATH, PT_REQ, PT_RESPONSE, PT_TXT_MSG):
            ok = len(p) > 2 + CIPHER_MAC_SIZE
        elif t == PT_ANON_REQ:
            ok = len(p) > 1 + PUB_KEY_SIZE + 2
        elif t in (PT_GRP_TXT, PT_GRP_DATA):
            ok = len(p) > 1 + 2
        elif t == PT_ADVERT:
            ok = len(p) >= PUB_KEY_SIZE + 4 + SIGNATURE_SIZE
        else:
            return [], "packet type", "never flooded"         # traces, multipart, control, raw: not flood-relayed
        if not ok:
            return [], "malformed", ""
        if self.was_seen(pkt):
            return [], "duplicate", ""
        self.seen_mark(pkt)
        if t == PT_ADVERT and not ed25519_verify(p[:32], p[36:100], p[:36] + p[100:100 + MAX_ADVERT_DATA_SIZE]):
            return [], "bad signature", ""
        f = self.filters(pkt, c)
        if f:
            return [], f[0], f[1]
        n, sz = pkt.hop_count, pkt.hash_size
        if (n + 1) * sz > MAX_PATH_SIZE or n + 1 > 63:     # (the hop count is 6 bits)
            return [], "hops", "path full"
        if n >= c["max_flood_hops"] or (t == PT_ADVERT and n >= RPT_FLOOD_MAX_ADVERT):
            return [], "hops", "%d hops" % n
        if not self.scope_ok(pkt, c):
            return [], "region", "unscoped" if pkt.route_type == ROUTE_FLOOD else ""
        if self.looped(pkt, c):
            return [], "loop", ""
        targets = self.targets(radio, c)
        if not targets:
            return [], "repeat off", ""
        fwd = pkt.copy()
        fwd.path = pkt.path[:n * sz] + self.ident.pub_key[:sz]      # append our id at the packet's id size
        fwd.path_len = (pkt.path_len & ~63) | (n + 1)
        return [(r, fwd, n + 1, RPT_TX_DELAY_FACTOR) for r in targets], None, ""   # closer sources first

    def eval_direct(self, radio, pkt, c):
        """Direct routing: we are the next hop -> consume our hop and pass it on (Mesh.cpp)."""
        sz = pkt.hash_size
        if pkt.path[:sz] != self.ident.pub_key[:sz]:
            return [], "not for us", ""
        p, t = pkt.payload, pkt.ptype
        if t == PT_MULTIPART:
            if not (len(p) >= 5 and (p[0] & 0x0F) == PT_ACK):
                return [], "packet type", "multipart"
            tmp = Packet(PT_ACK, p[1:])                     # a multipart ACK: forwarded as a plain ACK
            tmp.header, tmp.path_len, tmp.path = pkt.header, pkt.path_len, pkt.path
            if self.was_seen(tmp):
                return [], "duplicate", ""
            self.seen_mark(tmp)
            f = self.filters(pkt, c)
            if f:
                return [], f[0], f[1]
            fwd = self.direct_ack(self.consume_hop(tmp))
            targets = self.direct_targets(radio, self.next_hop(fwd), c)
            if not targets:
                return [], "repeat off", ""
            return [(r, fwd, 0, None) for r in targets], None, ""
        if self.was_seen(pkt):
            return [], "duplicate", ""
        self.seen_mark(pkt)
        f = self.filters(pkt, c)
        if f:
            return [], f[0], f[1]
        fwd = self.consume_hop(pkt)
        if t == PT_ACK:
            fwd = self.direct_ack(fwd)
            factor = None                                   # ACKs go straight out
        else:
            factor = RPT_DIRECT_TX_DELAY_FACTOR
        targets = self.direct_targets(radio, self.next_hop(fwd), c)
        if not targets:
            return [], "repeat off", ""
        return [(r, fwd, 0, factor) for r in targets], None, ""

    @staticmethod
    def next_hop(fwd):
        """The id the forwarded packet is addressed to: the next path entry, or on the last hop the destination
        hash in the payload (REQ/RESPONSE/TXT_MSG/PATH/ANON_REQ). None if unknown."""
        if fwd.hop_count:
            return fwd.path[:fwd.hash_size]
        if fwd.ptype in (PT_REQ, PT_RESPONSE, PT_TXT_MSG, PT_PATH, PT_ANON_REQ) and fwd.payload:
            return fwd.payload[:1]
        return None

    @staticmethod
    def consume_hop(pkt):
        fwd = pkt.copy()
        sz = pkt.hash_size
        fwd.path = pkt.path[sz:path_bytes(pkt.path_len)]
        fwd.path_len = (pkt.path_len & ~63) | (pkt.hop_count - 1)
        return fwd

    @staticmethod
    def direct_ack(pkt):
        """Mesh::routeDirectRecvAcks (multi_acks 0): a fresh direct ACK on the remaining path."""
        ack = Packet(PT_ACK, pkt.payload)
        ack.header = (ack.header & ~0x03) | ROUTE_DIRECT
        ack.path_len, ack.path = pkt.path_len, pkt.path
        return ack

    def eval_trace(self, radio, pkt, c):
        """Mesh.cpp TRACE: if the next entry in its route is us, append the SNR we heard it at and send it on."""
        p = pkt.payload
        if len(p) < 9 or pkt.path_len >= MAX_PATH_SIZE:
            return [], "malformed", ""
        es = 1 << (p[8] & 0x03)
        off = pkt.path_len * es
        if not (off < len(p) - 9 and p[9 + off:9 + off + es] == self.ident.pub_key[:es]):
            return [], "not for us", ""
        if self.was_seen(pkt):
            return [], "duplicate", ""
        self.seen_mark(pkt)
        f = self.filters(pkt, c)
        if f:
            return [], f[0], f[1]
        fwd = pkt.copy()
        fwd.path = pkt.path[:pkt.path_len] + struct.pack("b", max(-128, min(127, int(pkt.snr * 4))))
        fwd.path_len = pkt.path_len + 1
        noff = fwd.path_len * es
        nxt = p[9 + noff:9 + noff + es] if noff < len(p) - 9 else None    # None: back to the originator
        targets = self.direct_targets(radio, nxt, c)
        if not targets:
            return [], "repeat off", ""
        return [(r, fwd, 5, RPT_DIRECT_TX_DELAY_FACTOR) for r in targets], None, ""

    def eval_control(self, radio, pkt, c):
        """Answer node discovery (MyMesh::onControlDataRecv) on the radio it came in on: at most 4 answers every
        2 minutes, randomised."""
        p = pkt.payload
        if (p[0] & 0xF0) != 0x80 or len(p) < 6:
            return [], "packet type", "control"
        if not c["relay_enabled"]:
            return [], "relay off", ""
        now = now_s()
        if now < self.disc_window[0] + 120:                 # RateLimiter(4, 120)
            self.disc_window[1] += 1
            if self.disc_window[1] > 4:
                return [], "airtime cap", "discovery rate limit"
        else:
            self.disc_window[:] = [now, 1]
        since = struct.unpack_from("<I", p, 6)[0] if len(p) >= 10 else 0
        if not (p[1] & (1 << ADV_TYPE_REPEATER)) or self.started < since:
            return [], "not for us", "discovery for other node types"
        prefix_only = p[0] & 1
        data = bytes([0x90 | ADV_TYPE_REPEATER]) + struct.pack("b", max(-128, min(127, int(pkt.snr * 4)))) + p[2:6] \
            + self.ident.pub_key[:8 if prefix_only else PUB_KEY_SIZE]
        resp = Packet(PT_CONTROL, data)
        resp.header = (resp.header & ~0x03) | ROUTE_DIRECT
        resp.path_len, resp.path = 0, b""
        return [(radio, resp, 0, RPT_TX_DELAY_FACTOR * 4)], None, ""

    # ---------------------------------------------------------------- identity and adverts

    def set_identity(self, key_hex):
        self.ident = RepeaterIdentity(bytes.fromhex(key_hex))

    def send_advert(self, flood):
        c = self.cfg
        pkt = make_advert(self.ident, c["name"], c["lat"], c["lon"])
        self.seen_mark(pkt)                                 # never relay our own advert back
        sent = []
        for r in self.radios:
            rc = c[r.name]
            if not (rc["enabled"] and rc["advert"]):
                continue
            a = pkt.copy()
            if flood:
                a.header = (a.header & ~0x03) | ROUTE_FLOOD
                a.path_len, a.path = rc["hash_mode"] << 6, b""
            else:
                a.header = (a.header & ~0x03) | ROUTE_DIRECT
                a.path_len, a.path = 0, b""
            if r.enqueue(a, 0, own=True) is None:
                sent.append(r.name)
        if sent:
            self.stats["adverts_sent"] += 1
            log.info("sent %s advert on %s", "flood" if flood else "zero-hop", ", ".join(sent))
        return sent

    # ---------------------------------------------------------------- web state

    def make_snapshot(self):
        c, now = self.cfg, time.time()
        nowm = time.monotonic()
        radios = []
        for r in self.radios:
            rc = c[r.name]
            radios.append(dict(
                name=r.name, enabled=rc["enabled"], status=r.status, serial=rc["serial"],
                freq_mhz=rc["freq_mhz"], bw_khz=rc["bw_khz"], sf=rc["sf"], cr=rc["cr"], tx_power_dbm=rc["tx_power_dbm"],
                repeat_same=rc["repeat_same"], repeat_cross=rc["repeat_cross"],
                reported=None if r.reported is None else dict(zip(("freq_hz", "bw_hz", "sf", "cr"), r.reported)),
                queued=r.queued(), airtime_used=r.airtime_used(), airtime_cap=rc["airtime_pct"],
                rx=self.rx[r.idx]["rx"], relays_out=self.rx[r.idx]["relays_out"], rx_airtime_s=self.rx[r.idx]["rx_airtime_ms"] // 1000,
                **{k: v for k, v in r.stats.items()}))
        neigh = []
        for e in sorted(self.neigh.values(), key=lambda e: -e["last"]):
            radios_ = {RADIOS[i]: dict(ago=int(now - ts), snr=e["snr"].get(i)) for i, ts in e["radios"].items()
                       if now - ts < NEIGHBOUR_TTL_S}
            if radios_:
                neigh.append(dict(id=e["id"][:16], name=e["name"] or self.name_for(e["id"]), radios=radios_,
                                  ago=int(now - e["last"])))
        totals = self.totals + self.stats
        return dict(
            version=VERSION, name=c["name"], pub=self.ident.pub_key.hex(), uptime=int(nowm - self.boot),
            relay_enabled=c["relay_enabled"], stats=dict(self.stats), totals=dict(totals), radios=radios,
            neighbours=neigh[:100], log=list(self.log)[-100:][::-1],
            next_zero_advert=int(self.next_zero_advert - nowm) if c["advert_interval_min"] else None,
            next_flood_advert=int(self.next_flood_advert - nowm) if c["flood_advert_interval_h"] else None,
            login_enabled=bool(c["web_password"]))

    # ---------------------------------------------------------------- settings (web threads)

    def update_settings(self, body):
        with self.cfg_lock:
            old = self.cfg
            new = apply_settings(old, body)
            self.commit(new)
        if any(old[k] != new[k] for k in ("name", "lat", "lon")):
            self.rxq.put(("advert_soon",))
        return new

    def update_identity(self, key_hex=None):
        key_hex = (key_hex or generate_private_key()).strip().lower()
        ident = RepeaterIdentity(bytes.fromhex(key_hex))    # (raises ValueError on a bad key)
        with self.cfg_lock:
            new = normalise(dict(self.cfg, private_key=key_hex))
            self.commit(new)
            self.ident = ident
        self.rxq.put(("advert_soon",))
        return ident.pub_key.hex()

    def update_password(self, pw):
        if len(pw) < 6:
            raise ValueError("password: at least 6 characters")
        with self.cfg_lock:
            self.commit(dict(self.cfg, web_password=hash_web_password(pw)))

    def commit(self, new):
        if self.cfg_path:
            save_config(self.cfg_path, new)
        self.cfg = new
        for r in self.radios:
            r.wake()


# ============================================================================
# Web UI
# ============================================================================

class WebUI:
    """Read-only stats for everyone; the admin panel after logging in with web_password."""

    SESSION_S = 12 * 3600

    def __init__(self, app):
        import http.server
        self.app = app
        sessions, slock = {}, threading.Lock()
        last_advert = [float("-inf")]
        page = (PAGE_HTML.encode(), gzip.compress(PAGE_HTML.encode(), 6))

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _token(self):
                for part in (self.headers.get("Cookie") or "").split(";"):
                    k, _, v = part.strip().partition("=")
                    if k == "mcx_session":
                        return v
                return None

            def _is_admin(self):
                tok = self._token()
                if not tok or not app.cfg["web_password"]:
                    return False
                with slock:
                    exp = sessions.get(tok)
                    if exp is None or exp < time.monotonic():
                        sessions.pop(tok, None)
                        return False
                    return True

            def _body(self):
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                    if n > 65536:
                        return None
                    return json.loads(self.rfile.read(n) or b"{}")
                except ValueError:
                    return None

            def _send(self, code, body, ctype="application/json", cookie=None, gz=False):
                b = body if isinstance(body, bytes) else body.encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(b)))
                if gz:
                    self.send_header("Content-Encoding", "gzip")
                    self.send_header("Vary", "Accept-Encoding")
                self.send_header("Cache-Control", "no-store")
                if cookie:
                    self.send_header("Set-Cookie", cookie)
                self.end_headers()
                try:
                    self.wfile.write(b)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass

            def _json(self, code, obj, cookie=None):
                return self._send(code, json.dumps(obj, default=str), cookie=cookie)

            def do_GET(self):
                path = self.path.split("?")[0]
                if path in ("/", "/index.html"):
                    gz = "gzip" in (self.headers.get("Accept-Encoding") or "")
                    return self._send(200, page[1] if gz else page[0], "text/html; charset=utf-8", gz=gz)
                if path == "/api/state":
                    admin = self._is_admin()
                    st = dict(app.snapshot, admin=admin)
                    if admin:
                        st["settings"] = public_settings(app.cfg)
                        st["packet_type_names"] = list(PT_NAMES.values())
                    return self._json(200, st)
                return self._json(404, {"error": "not found"})

            def do_POST(self):
                path = self.path.split("?")[0]
                if path == "/api/login":
                    body = self._body() or {}
                    if not app.cfg["web_password"]:
                        return self._json(403, {"error": "set web_password in config.json to enable the admin panel"})
                    if not check_web_password(str(body.get("password", "")), app.cfg["web_password"]):
                        time.sleep(1.0)                     # slow down guessing
                        return self._json(401, {"error": "wrong password"})
                    tok = secrets.token_hex(24)
                    with slock:
                        now_m = time.monotonic()
                        for k in [k for k, e in sessions.items() if e < now_m]:
                            del sessions[k]
                        sessions[tok] = now_m + WebUI.SESSION_S
                    return self._json(200, {"ok": True}, cookie="mcx_session=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=%d"
                                      % (tok, WebUI.SESSION_S))
                if path == "/api/logout":
                    tok = self._token()
                    with slock:
                        sessions.pop(tok, None)
                    return self._json(200, {"ok": True}, cookie="mcx_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
                if not self._is_admin():
                    return self._json(401, {"error": "log in first"})
                body = self._body()
                if body is None:
                    return self._json(400, {"error": "bad request"})
                try:
                    if path == "/api/settings":
                        app.update_settings(body)
                        return self._json(200, {"ok": True, "settings": public_settings(app.cfg)})
                    if path == "/api/identity":
                        if body.get("generate"):
                            pub = app.update_identity(None)
                        else:
                            key = str(body.get("private_key", "")).strip()
                            if not re.match(r"^[0-9a-fA-F]+$", key) or len(key) not in (64, 128):
                                raise ValueError("private key: 64 or 128 hex characters")
                            pub = app.update_identity(key)
                        return self._json(200, {"ok": True, "pub": pub})
                    if path == "/api/password":
                        app.update_password(str(body.get("password", "")))
                        return self._json(200, {"ok": True})
                    if path == "/api/advert":
                        with slock:
                            if time.monotonic() - last_advert[0] < 10:
                                return self._json(429, {"error": "an advert was just sent: wait a few seconds"})
                            last_advert[0] = time.monotonic()
                        app.rxq.put(("advert", bool(body.get("flood"))))
                        return self._json(200, {"ok": True})
                    if path == "/api/purge":
                        n = sum(r.purge() for r in app.radios)
                        return self._json(200, {"ok": True, "purged": n})
                except ValueError as e:
                    return self._json(400, {"error": str(e)})
                except OSError as e:
                    return self._json(500, {"error": "could not save config: %s" % e})
                return self._json(404, {"error": "not found"})

        c = app.cfg
        self.server = http.server.ThreadingHTTPServer((c["listen_address"], c["listen_port"]), H)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, name="web", daemon=True).start()
        log.info("web UI on http://%s:%d/", c["listen_address"], c["listen_port"])


PAGE_HTML = r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>mcxrepeater</title>
<meta name="referrer" content="strict-origin-when-cross-origin">
<style>
:root{--bg:#111418;--card:#1a1f26;--line:#2a313b;--fg:#d8dee6;--dim:#8a94a3;--acc:#5cb3ff;--ok:#4caf7a;--warn:#e0a83e;--bad:#e05a5a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.4 system-ui,sans-serif}
header{padding:12px 18px;border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;gap:18px;align-items:baseline}
header h1{font-size:18px;margin:0}.dim{color:var(--dim)}main{padding:14px 18px;display:grid;gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;overflow-x:auto}
.card h2{font-size:14px;margin:0 0 8px;color:var(--acc);text-transform:uppercase;letter-spacing:.04em}
.hdesc{color:var(--dim);font-weight:400;text-transform:none;letter-spacing:0;font-size:12px;margin-left:8px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:4px 8px;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:top}
th{color:var(--dim);font-weight:500}.tag{padding:1px 6px;border-radius:4px;font-size:12px}
.relayed,.answered{background:#24382c;color:var(--ok)}.dropped{background:#3d2424;color:var(--bad)}
button{background:#2a313b;color:var(--fg);border:1px solid var(--line);border-radius:4px;padding:3px 10px;cursor:pointer}
button.pri{border-color:var(--acc)}
.mono{font-family:ui-monospace,monospace;word-break:break-all;white-space:normal}
.good{color:var(--ok)}.mid{color:var(--warn)}.poor{color:var(--bad)}.small{font-size:12px}
.kpis{display:flex;flex-wrap:wrap;gap:22px}.kpi b{font-size:18px;display:block}
.modal{position:fixed;inset:0;background:#000a;display:none;align-items:center;justify-content:center;z-index:3000}
.mbox{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px 18px;width:300px}.mbox h3{margin:0 0 10px;font-size:15px}
input,select{padding:4px 6px;background:#0d1014;border:1px solid var(--line);border-radius:4px;color:var(--fg);font:inherit}
.mbox input{width:100%}
.row{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;margin:8px 0}.row label{display:flex;gap:6px;align-items:center}
input[type=checkbox]{transform:scale(1.2)}input.num{width:90px}input.wide{width:320px;max-width:100%}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:14px}
.sub{background:#151a20;border:1px solid var(--line);border-radius:6px;padding:10px 12px}.sub h3{margin:0 0 6px;font-size:14px}
.form td:first-child{color:var(--dim);width:150px}.form td{border:none;padding:3px 6px;white-space:normal}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0}.chip{background:#243447;border-radius:12px;padding:2px 4px 2px 10px;display:inline-flex;gap:6px;align-items:center}
.chip button{border:none;background:transparent;color:var(--dim);padding:0 6px}.chip button:hover{color:var(--bad)}
.types{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:6px 12px;margin:8px 0}
.msg{margin-left:8px}.note{margin-top:8px;padding:8px 10px;border-left:3px solid var(--acc);background:#151a20;color:var(--dim);font-size:12px}
.admin{display:none;order:1}body.isadmin .admin{display:block}#logcard{order:2}
</style></head><body>
<header><h1 id="rname">mcxrepeater</h1><span class="dim" id="rinfo"></span><span id="rrelay"></span>
<span style="margin-left:auto"><span id="who" class="dim small"></span> <button id="loginbtn" onclick="loginClick()">Log in</button></span>
<div class="dim small mono" style="flex-basis:100%">public key <span id="rpub"></span></div></header>
<div id="loginbox" class="modal"><div class="mbox"><h3>Admin log in</h3><input id="pw" type="password" placeholder="Password" onkeydown="if(event.key==='Enter')doLogin()">
<div id="loginerr" class="poor small"></div><div style="margin-top:10px;display:flex;gap:8px;justify-content:flex-end"><button onclick="closeLogin()">Cancel</button><button class="pri" onclick="doLogin()">Log in</button></div></div></div>
<main>
<div class="card"><div class="kpis" id="kpis"></div></div>
<div class="card"><h2>Radios</h2><table id="radios"></table></div>
<div class="card"><h2>Neighbours <span class="hdesc">repeaters and nodes heard directly; direct packets go out on the radio their next hop was heard on</span></h2><table id="neigh"></table></div>
<div class="card"><h2>Dropped <span class="hdesc">since start</span></h2><div class="kpis" id="drops"></div></div>
<div class="card" id="logcard"><h2>Recent packets</h2><table id="plog"></table></div>

<div class="card admin"><h2>Identity <span class="hdesc">one key for both radios; the modems' own keys aren't used</span></h2>
<div class="row">Public key <span id="idpub" class="mono"></span></div>
<div class="row"><label>Private key <input id="idkey" class="wide" type="password" autocomplete="new-password" placeholder="64 or 128 hex characters"></label>
<button class="pri" onclick="setKey()">Apply</button><button onclick="genKey()">Generate new key</button><span id="idmsg" class="msg small"></span></div>
<div class="note">The private key is never shown again once saved. Changing it makes this a new repeater to the mesh: other nodes' routes through the old key stop working.</div></div>

<div class="card admin"><h2>Adverts</h2>
<div class="row"><label>Name <input id="a_name" maxlength="31"></label><label>Latitude <input id="a_lat" class="num" placeholder="none"></label><label>Longitude <input id="a_lon" class="num" placeholder="none"></label></div>
<div class="row"><label>Zero-hop advert every <input id="a_zero" class="num" type="number" min="0" max="1440"> min</label><label>Flood advert every <input id="a_flood" class="num" type="number" min="0" max="168"> h</label><span class="dim small">0 = off</span></div>
<div class="row"><button class="pri" onclick="saveAdverts()">Apply</button><button onclick="advertNow(false)">Send zero-hop advert now</button><button onclick="advertNow(true)">Send flood advert now</button><span id="advmsg" class="msg small"></span><span id="advnext" class="dim small"></span></div>
<div class="note">Which radios send adverts, and their path id size (hash mode), are set per radio below.</div></div>

<div class="card admin"><h2>Radio settings</h2><div class="grid2" id="rforms"></div>
<div class="row"><button class="pri" onclick="saveRadios()">Apply</button><span id="radmsg" class="msg small"></span></div>
<div class="note">Repeat "same frequency" relays what this radio hears back out on this radio; "cross frequency" relays it out on the other radio. Hash mode is the path id size (1/2/3 bytes) of adverts this repeater sends; relayed packets keep their own.</div></div>

<div class="card admin"><h2>Relay</h2>
<div class="row"><label><input type="checkbox" id="r_on"> Relay packets</label><span class="dim small">off = adverts only, nothing relayed</span></div>
<div class="row"><label>Max flood hops <input id="r_hops" class="num" type="number" min="1" max="64"></label>
<label>Loop detection <select id="r_loop"><option>off</option><option>minimal</option><option>moderate</option><option>strict</option></select></label></div>
<div class="row"><button class="pri" onclick="saveRelay()">Apply</button><button onclick="purge()">Drop queued relays</button><span id="relmsg" class="msg small"></span></div></div>

<div class="card admin"><h2>Regions <span class="hdesc">scoped floods carry a code from their region's name; direct packets are never filtered by region</span></h2>
<div class="row"><select id="g_mode"><option value="only">Only the following regions</option><option value="except">All regions except</option></select>
<label><input type="checkbox" id="g_unscoped"> Relay unscoped floods</label></div>
<div class="chips" id="g_list"></div>
<div class="row"><input id="g_new" placeholder="region name, e.g. usa-ca" onkeydown="if(event.key==='Enter')addRegion()"><button onclick="addRegion()">Add</button></div>
<div class="row"><button class="pri" onclick="saveRegions()">Apply</button><span id="regmsg" class="msg small"></span></div></div>

<div class="card admin"><h2>Packet types</h2>
<div class="row"><select id="t_mode"><option value="only">Only the following packet types</option><option value="except">All packet types except</option></select></div>
<div class="types" id="t_list"></div>
<div class="row"><button class="pri" onclick="saveTypes()">Apply</button><span id="typmsg" class="msg small"></span></div>
<div class="note">Blocking ACK or PATH breaks direct messages for everyone routing through this repeater. TRACE, MULTIPART, CONTROL and RAW_CUSTOM are never flood-relayed by MeshCore repeaters anyway.</div></div>

<div class="card admin"><h2>Blacklist</h2>
<div class="sub"><h3>Source key prefixes</h3>
<div class="chips" id="b_list"></div>
<div class="row"><input id="b_new" placeholder="e.g. 5b* or 5b98*" onkeydown="if(event.key==='Enter')addPrefix()"><button onclick="addPrefix()">Add</button></div>
<div class="note">Adverts and logins carry the full public key, so any prefix matches. Direct messages, requests and responses carry only the first byte of the sender's key: only 1-byte prefixes (like 5b*) block those.</div></div>
<div class="sub" style="margin-top:10px"><h3>Names in channels</h3>
<div class="chips" id="c_list"></div>
<div class="row"><input id="c_chan" placeholder="#channel or public"><input id="c_name" placeholder="sender name" onkeydown="if(event.key==='Enter')addChanName()"><button onclick="addChanName()">Add</button></div>
<div class="note">Works for the Public channel and #hashtag channels, whose keys are known.</div></div>
<div class="row"><button class="pri" onclick="saveBlacklist()">Apply</button><span id="blmsg" class="msg small"></span></div></div>

<div class="card admin"><h2>Web password</h2>
<div class="row"><input id="w_pw" type="password" autocomplete="new-password" placeholder="new password"><button class="pri" onclick="savePw()">Apply</button><span id="pwmsg" class="msg small"></span></div></div>
</main>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let ADMIN=false,LOGIN_ON=false,S=null,FILLED=false,REG=[],PRE=[],CHN=[],TYPES=[];
const BWS=[7.8,10.4,15.6,20.8,31.25,41.7,62.5,125,250,500];
function ago(s){if(s==null)return"";if(s<60)return s+"s";if(s<3600)return Math.floor(s/60)+"m";if(s<86400)return Math.floor(s/3600)+"h"+String(Math.floor(s%3600/60)).padStart(2,"0");return Math.floor(s/86400)+"d"}
function tm(t){return new Date(t*1000).toLocaleTimeString()}
function msg(id,ok,text){const e=$(id);e.className="msg small "+(ok?"good":"poor");e.textContent=text;if(ok)setTimeout(()=>{if(e.textContent===text)e.textContent=""},4000)}
async function post(url,body){let r;try{r=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body||{})})}catch(e){return{ok:false,error:"no connection"}}
 let d={};try{d=await r.json()}catch(e){}if(r.status===401){ADMIN=false;document.body.classList.remove("isadmin");return{ok:false,error:"your admin session has expired: log in again"}}
 return r.ok?Object.assign({ok:true},d):{ok:false,error:d.error||("failed ("+r.status+")")}}
async function load(){let st;try{st=await (await fetch("api/state")).json()}catch(e){return}S=st;render(st);
 if(st.admin!==ADMIN){ADMIN=st.admin;FILLED=false}LOGIN_ON=st.login_enabled;document.body.classList.toggle("isadmin",ADMIN);
 $("loginbtn").textContent=ADMIN?"Log out":"Log in";$("who").textContent=ADMIN?"admin":"";
 if(ADMIN&&st.settings&&!FILLED){fill(st.settings,st.packet_type_names);FILLED=true}}
function render(st){
 $("rname").textContent=st.name||"mcxrepeater";document.title=st.name||"mcxrepeater";
 $("rinfo").textContent=(st.version||"")+" · up "+ago(st.uptime);$("rpub").textContent=st.pub||"";$("idpub").textContent=st.pub||"";
 $("rrelay").innerHTML=st.relay_enabled?'<span class="good">relaying</span>':'<span class="poor">relay off</span>';
 const s=st.stats||{},t=st.totals||{};
 const k=[["Received",s.rx,t.rx],["Relayed",s.relayed,t.relayed],["Floods",s.relayed_flood,t.relayed_flood],["Direct",s.relayed_direct,t.relayed_direct],["ACKs",s.relayed_ack,t.relayed_ack],["Traces",s.relayed_trace,t.relayed_trace],["Dropped",s.dropped,t.dropped],["Adverts sent",s.adverts_sent,t.adverts_sent]];
 $("kpis").innerHTML=k.map(x=>'<div class="kpi"><b>'+(x[1]||0)+'</b><span class="dim small">'+x[0]+' · '+(x[2]||0)+' total</span></div>').join("");
 $("radios").innerHTML="<tr><th>Radio</th><th>Status</th><th>Settings</th><th>Repeat</th><th>Received</th><th>Relays out</th><th>Sent</th><th>Airtime</th><th>Queue</th><th>TX errors</th></tr>"+
  (st.radios||[]).map(r=>{const rep=[r.repeat_same?"same":"",r.repeat_cross?"cross":""].filter(x=>x).join(" + ")||"off";
   const stc=!r.enabled?"dim":r.status==="ok"?"good":"poor";
   return "<tr><td><b>"+esc(r.name)+"</b><div class='dim small'>"+esc(r.serial)+"</div></td><td class='"+stc+"' style='white-space:normal;max-width:260px'>"+esc(r.enabled?r.status:"disabled")+"</td><td>"+r.freq_mhz+" MHz<div class='dim small'>BW "+r.bw_khz+" · SF"+r.sf+" · CR4/"+r.cr+(r.tx_power_dbm!=null?" · "+r.tx_power_dbm+" dBm":"")+"</div></td><td>"+rep+"</td><td>"+r.rx+"</td><td>"+r.relays_out+"</td><td>"+r.tx+"</td><td>"+r.airtime_used+"%<div class='dim small'>cap "+r.airtime_cap+"%</div></td><td>"+r.queued+"</td><td>"+(r.tx_errors+r.drop_queue+r.drop_airtime?r.tx_errors+" · full "+r.drop_queue+" · cap "+r.drop_airtime:"0")+"</td></tr>"}).join("");
 const nb=st.neighbours||[];
 $("neigh").innerHTML=nb.length?"<tr><th>Id</th><th>Name</th><th>radio1</th><th>radio2</th><th>Last heard</th></tr>"+nb.map(n=>{const c=x=>{const v=n.radios[x];return v?(v.snr!=null?v.snr+" dB · ":"")+ago(v.ago)+" ago":"<span class='dim'>-</span>"};
  return "<tr><td class='mono'>"+esc(n.id.toUpperCase())+"</td><td>"+esc(n.name||"")+"</td><td>"+c("radio1")+"</td><td>"+c("radio2")+"</td><td>"+ago(n.ago)+" ago</td></tr>"}).join(""):"<tr><td class='dim'>none heard yet</td></tr>";
 const d=Object.keys(s).filter(x=>x.startsWith("drop_")&&s[x]).sort((a,b)=>s[b]-s[a]);
 $("drops").innerHTML=d.length?d.map(x=>'<div class="kpi"><b>'+s[x]+'</b><span class="dim small">'+esc(x.slice(5).replace(/_/g," "))+'</span></div>').join(""):'<span class="dim">nothing yet</span>';
 const lg=st.log||[];
 $("plog").innerHTML=lg.length?"<tr><th>Time</th><th>Radio</th><th>Type</th><th>Route</th><th>Hops</th><th>SNR</th><th>RSSI</th><th>Source</th><th>Result</th></tr>"+lg.map(e=>"<tr><td>"+tm(e.t)+"</td><td>"+e.radio+"</td><td>"+esc(e.type)+"</td><td>"+esc(e.route)+"</td><td>"+(e.hops==null?"":e.hops)+"</td><td>"+e.snr+"</td><td>"+e.rssi+"</td><td class='mono'>"+esc((e.src||"").toUpperCase())+"</td><td><span class='tag "+esc(e.result)+"'>"+esc(e.result)+"</span> <span class='dim small'>"+esc(e.reason||"")+"</span></td></tr>").join(""):"<tr><td class='dim'>nothing received yet</td></tr>";
 if(ADMIN)$("advnext").textContent=(st.next_zero_advert!=null?"next zero-hop in "+ago(Math.max(0,st.next_zero_advert)):"")+(st.next_flood_advert!=null?" · next flood in "+ago(Math.max(0,st.next_flood_advert)):"")}
function radioForm(n,r){const o=(vals,cur,lab)=>vals.map(v=>'<option value="'+v+'"'+(v==cur?" selected":"")+'>'+(lab?lab(v):v)+'</option>').join("");
 const ck=(k,t)=>'<label><input type="checkbox" id="'+n+'_'+k+'"'+(r[k]?" checked":"")+'> '+t+'</label>';
 return '<div class="sub"><h3>'+n+'</h3><table class="form">'+
 '<tr><td>Enabled</td><td>'+ck("enabled","")+'</td></tr>'+
 '<tr><td>Serial port</td><td><input id="'+n+'_serial" value="'+esc(r.serial)+'"> <input id="'+n+'_baud" class="num" type="number" value="'+r.baud+'" title="baud"></td></tr>'+
 '<tr><td>Frequency</td><td><input id="'+n+'_freq_mhz" class="num" value="'+r.freq_mhz+'"> MHz</td></tr>'+
 '<tr><td>Bandwidth</td><td><select id="'+n+'_bw_khz">'+o(BWS,r.bw_khz)+'</select> kHz</td></tr>'+
 '<tr><td>Spreading factor</td><td><select id="'+n+'_sf">'+o([5,6,7,8,9,10,11,12],r.sf)+'</select></td></tr>'+
 '<tr><td>Coding rate</td><td><select id="'+n+'_cr">'+o([5,6,7,8],r.cr,v=>"4/"+v)+'</select></td></tr>'+
 '<tr><td>TX power</td><td><input id="'+n+'_tx_power_dbm" class="num" placeholder="modem default" value="'+(r.tx_power_dbm==null?"":r.tx_power_dbm)+'"> dBm</td></tr>'+
 '<tr><td>Hash mode</td><td><select id="'+n+'_hash_mode">'+o([0,1,2],r.hash_mode,v=>(v+1)+"-byte ids")+'</select></td></tr>'+
 '<tr><td>Repeat</td><td>'+ck("repeat_same","Same frequency")+ck("repeat_cross","Cross frequency")+'</td></tr>'+
 '<tr><td>Adverts</td><td>'+ck("advert","Send adverts on this radio")+'</td></tr>'+
 '<tr><td>Airtime cap</td><td><input id="'+n+'_airtime_pct" class="num" type="number" min="1" max="100" value="'+r.airtime_pct+'"> % for relays</td></tr>'+
 '<tr><td>KISS</td><td>TXDELAY <input id="'+n+'_kiss_txdelay" class="num" type="number" value="'+r.kiss_txdelay+'"> persistence <input id="'+n+'_kiss_persistence" class="num" type="number" value="'+r.kiss_persistence+'"> slot <input id="'+n+'_kiss_slottime" class="num" type="number" value="'+r.kiss_slottime+'"></td></tr>'+
 '</table></div>'}
function fill(c,types){
 $("a_name").value=c.name;$("a_lat").value=c.lat==null?"":c.lat;$("a_lon").value=c.lon==null?"":c.lon;$("a_zero").value=c.advert_interval_min;$("a_flood").value=c.flood_advert_interval_h;
 $("rforms").innerHTML=radioForm("radio1",c.radio1)+radioForm("radio2",c.radio2);
 $("r_on").checked=c.relay_enabled;$("r_hops").value=c.max_flood_hops;$("r_loop").value=c.loop_detect;
 $("g_mode").value=c.regions.mode;$("g_unscoped").checked=c.regions.relay_unscoped;REG=c.regions.list.slice();chips();
 if(types)TYPES=types;$("t_mode").value=c.packet_types.mode;
 $("t_list").innerHTML=TYPES.map(t=>'<label><input type="checkbox" class="ptype" value="'+t+'"'+(c.packet_types.list.includes(t)?" checked":"")+'> '+t+'</label>').join("");
 PRE=c.blacklist.prefixes.slice();CHN=c.blacklist.channel_names.map(x=>Object.assign({},x));chips()}
function chips(){
 $("g_list").innerHTML=REG.map((r,i)=>'<span class="chip">#'+esc(r)+'<button onclick="REG.splice('+i+',1);chips()">✕</button></span>').join("")||'<span class="dim small">no regions listed</span>';
 $("b_list").innerHTML=PRE.map((r,i)=>'<span class="chip mono">'+esc(r)+'<button onclick="PRE.splice('+i+',1);chips()">✕</button></span>').join("")||'<span class="dim small">none</span>';
 $("c_list").innerHTML=CHN.map((r,i)=>'<span class="chip">'+esc(r.name)+' <span class="dim">in '+esc(r.channel)+'</span><button onclick="CHN.splice('+i+',1);chips()">✕</button></span>').join("")||'<span class="dim small">none</span>'}
function addRegion(){const v=$("g_new").value.trim().replace(/^#/,"");if(v&&!REG.includes(v))REG.push(v);$("g_new").value="";chips()}
function addPrefix(){let v=$("b_new").value.trim().toLowerCase();if(!v)return;if(!v.endsWith("*")&&v.length<64)v+="*";if(!PRE.includes(v))PRE.push(v);$("b_new").value="";chips()}
function addChanName(){const c=$("c_chan").value.trim(),n=$("c_name").value.trim();if(!c||!n)return;CHN.push({channel:c,name:n});$("c_name").value="";chips()}
async function apply(body,id,okText){const r=await post("api/settings",body);if(r.ok){msg(id,true,okText||"Saved");fill(r.settings);FILLED=true}else msg(id,false,r.error);return r}
function numOrNull(v){v=String(v).trim();return v===""?null:Number(v)}
function saveAdverts(){apply({name:$("a_name").value,lat:numOrNull($("a_lat").value),lon:numOrNull($("a_lon").value),advert_interval_min:Number($("a_zero").value),flood_advert_interval_h:Number($("a_flood").value)},"advmsg")}
function readRadio(n){const g=k=>$(n+"_"+k),r={};
 for(const k of ["enabled","repeat_same","repeat_cross","advert"])r[k]=g(k).checked;
 r.serial=g("serial").value.trim();for(const k of ["baud","freq_mhz","bw_khz","sf","cr","hash_mode","airtime_pct","kiss_txdelay","kiss_persistence","kiss_slottime"])r[k]=Number(g(k).value);
 r.tx_power_dbm=numOrNull(g("tx_power_dbm").value);return r}
function saveRadios(){apply({radio1:readRadio("radio1"),radio2:readRadio("radio2")},"radmsg","Saved: the radios are being reconfigured")}
function saveRelay(){apply({relay_enabled:$("r_on").checked,max_flood_hops:Number($("r_hops").value),loop_detect:$("r_loop").value},"relmsg")}
function saveRegions(){apply({regions:{mode:$("g_mode").value,relay_unscoped:$("g_unscoped").checked,list:REG}},"regmsg")}
function saveTypes(){apply({packet_types:{mode:$("t_mode").value,list:[...document.querySelectorAll(".ptype:checked")].map(x=>x.value)}},"typmsg")}
function saveBlacklist(){apply({blacklist:{prefixes:PRE,channel_names:CHN}},"blmsg")}
async function purge(){const r=await post("api/purge");msg("relmsg",r.ok,r.ok?"dropped "+r.purged+" queued packets":r.error)}
async function advertNow(flood){const r=await post("api/advert",{flood:flood});msg("advmsg",r.ok,r.ok?(flood?"flood":"zero-hop")+" advert queued":r.error)}
async function setKey(){const k=$("idkey").value.trim();if(!k)return;if(!confirm("Replace this repeater's key? It becomes a new repeater to the mesh."))return;
 const r=await post("api/identity",{private_key:k});if(r.ok){$("idkey").value="";msg("idmsg",true,"Saved. Public key "+r.pub.slice(0,16).toUpperCase()+"…");load()}else msg("idmsg",false,r.error)}
async function genKey(){if(!confirm("Generate a new key? This becomes a new repeater to the mesh."))return;
 const r=await post("api/identity",{generate:true});if(r.ok){msg("idmsg",true,"New key. Public key "+r.pub.slice(0,16).toUpperCase()+"…");load()}else msg("idmsg",false,r.error)}
async function savePw(){const r=await post("api/password",{password:$("w_pw").value});if(r.ok)$("w_pw").value="";msg("pwmsg",r.ok,r.ok?"Password changed":r.error)}
function loginClick(){if(ADMIN){fetch("api/logout",{method:"POST"}).then(load);return}
 if(!LOGIN_ON){alert("Set web_password in config.json and restart to enable the admin panel.");return}$("loginbox").style.display="flex";$("pw").focus()}
function closeLogin(){$("loginbox").style.display="none";$("pw").value="";$("loginerr").textContent=""}
async function doLogin(){const r=await post("api/login",{password:$("pw").value});if(r.ok){closeLogin();load()}else $("loginerr").textContent=r.error}
load();setInterval(load,2000);
</script></body></html>
"""


# ============================================================================
# Main
# ============================================================================

def prepare_config(path):
    """Load config.json; on first start fill in a private key and hash a plain-text web password, then save."""
    if not os.path.exists(path):
        example = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.example.json")
        sys.exit("no %s - copy %s to it and edit the serial ports, frequencies and web_password" % (path, example))
    try:
        cfg = load_config(path)
    except ValueError as e:
        sys.exit("%s: %s" % (path, e))
    changed = False
    if not cfg["private_key"]:
        cfg["private_key"] = generate_private_key()
        log.info("generated a new repeater key")
        changed = True
    if cfg["web_password"] and not cfg["web_password"].startswith("pbkdf2_sha256$"):
        cfg["web_password"] = hash_web_password(cfg["web_password"])
        log.info("web_password hashed in %s", path)
        changed = True
    if changed:
        save_config(path, cfg)
    return cfg


def main():
    ap = argparse.ArgumentParser(description="Two-radio MeshCore repeater over KISS modems")
    ap.add_argument("--config", default="config.json")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(threadName)s %(message)s")
    sys.setswitchinterval(0.001)                            # 1 ms thread slices: readers run sooner
    cfg = prepare_config(args.config)
    logging.getLogger().setLevel(getattr(logging, cfg["log_level"].upper(), logging.INFO))
    app = Repeater(cfg, args.config)
    log.info("%s %r, public key %s", VERSION, cfg["name"], hexs(app.ident.pub_key))
    app.snapshot = app.make_snapshot()
    try:
        WebUI(app)
    except OSError as e:
        log.error("web UI could not start on %s:%s: %s", cfg["listen_address"], cfg["listen_port"], e)
    app.start()
    stop = threading.Event()
    import signal
    for s in (signal.SIGINT, signal.SIGTERM):
        signal.signal(s, lambda *a: stop.set())
    stop.wait()
    log.info("stopping")
    app.stop()


if __name__ == "__main__":
    main()
