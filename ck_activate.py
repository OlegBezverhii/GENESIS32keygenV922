#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
ck_activate.py - САМОДОСТАТОЧНЫЙ скрипт активации лицензии ICONICS/CrypKey.
Содержит ВСЁ внутри себя: mailslot-клиент NGN, кодеки ключей v5, сборку
Site Key, custom info (Options), работу с .glic и SiteKey.txt.
НЕ импортирует другие наши файлы - можно носить одним файлом.

Что делает (по умолчанию всё сразу):
  1) поднимает сервер CRP32002.NGN (если не запущен);
  2) InitCrypkey + GetSiteCode;
  3) ставит unlimited Site Key через сервер, перебирая siteCodeId
     (SaveSiteKey), т.к. siteCodeId привязан ко времени/состоянию;
  4) заливает entitlement (Options) из .glic командой SetCustomInfoBytes;
  5) пишет SiteKey.txt (поля Site Key и PNum в окне View License).

Запуск на целевом ПК от администратора:
    python ck_activate.py
    python ck_activate.py --level 38208 --options 0x2FFC --count 127 --network
    python ck_activate.py --client-units 5000 --product-limit 1000000
    python ck_activate.py --field 24=5000 --field 25=0x00DB0040
    python ck_activate.py --glic "C:\ProgramData\ICONICS\demo.glic"
    python ck_activate.py --pnum 5346
    python ck_activate.py --list-fields
    python ck_activate.py --dry-run

Только stdlib + ctypes (Windows).
"""

import argparse
import ctypes
import ctypes.wintypes as w
import os
import re
import struct
import subprocess
import time

# ============================================================================
# CONFIG
# ============================================================================
USER_KEY = (
    "89af42ae58311d53e1616e418cb1f49f2d1f35f4537ea06cb9be526b667f7cf3"
    "093b1172831f1d913fd686cc0fc9b4cb670dd626ee1e4f79e6bb5e837744ad0d"
    "a35d93fd175ae231d82dae749d133f7249177d383d54ba7a1970e6cf87583f64"
    "7ecbbc741be09b8dfd5c128ebf68187ac0f7411cb3af0379c448ed78a2c44e78"
)
MASTER_KEY = "F474817D546E74424FA5CD5CCF"
APP_PATH = r"C:\ProgramData\ICONICS\ICOLIC.exe"
NGN_PATH = r"C:\Program Files\ICONICS\SoftLic\CRP32002.NGN"

CHUNK = 0x168
PKT = 0x180
ACK = 0xC

LICENSE_FILES = [
    r"C:\ProgramData\ICONICS\IcoLic.key",
    r"C:\ProgramData\ICONICS\IcoLic.rst",
    r"C:\ProgramData\ICONICS\IcoLic.ent",
    r"C:\ProgramData\ICONICS\IcoLic.csb",
    r"C:\ProgramData\ICONICS\IcoLic.CIHS",
]
DEFAULT_SITEKEYTXT = os.path.join(
    os.environ.get("ProgramData", r"C:\ProgramData"), "ICONICS", "SiteKey.txt")

# ============================================================================
# ТРАНСПОРТ: CRC16 / XOR-поток / hex
# ============================================================================
def reverse_bits(b):
    r = b & 1
    for _ in range(7):
        b >>= 1
        r = (r * 2 + (b & 1)) & 0xFF
    return r


def crc16(data):
    v2 = 0xFFFF
    for b in data:
        v2 ^= (reverse_bits(b) << 8) & 0xFFFF
        for _ in range(8):
            v2 = ((v2 * 2) ^ 0x8005) & 0xFFFF if (v2 & 0x8000) else (v2 * 2) & 0xFFFF
    lo = reverse_bits((v2 >> 8) & 0xFF)
    hi = reverse_bits(v2 & 0xFF)
    return (hi << 8) | lo


def obf(data, decrypt):
    r, a, b, c = 0xBE, 0xE7, 0x64, 0xAF
    out = bytearray(len(data))
    for i, ch in enumerate(data):
        x = ch ^ r ^ a ^ b ^ c
        out[i] = x
        t = a ^ c
        a = (a ^ b) & 0xFF
        b = (b ^ r) & 0xFF
        c = t & 0xFF
        r = (r ^ (x if decrypt else ch)) & 0xFF
    return bytes(out)


def hex_encode(data):
    return "".join("%02X" % x for x in data).encode("ascii")


def hex_decode(s):
    s = s.decode("ascii", "ignore") if isinstance(s, bytes) else s
    out = bytearray()
    for i in range(0, len(s) - 1, 2):
        try:
            out.append(int(s[i:i + 2], 16))
        except ValueError:
            break
    return bytes(out)


def fold_user(s):
    h = 0
    for ch in s.encode("latin-1"):
        v = ch if ch < 128 else ch - 256
        h = (v * v * (h + 1)) & 0xFFFF
    return h


def fold_master(s):
    h = 0
    for ch in s.encode("latin-1"):
        v = ch if ch < 128 else ch - 256
        h = (v * (v + h)) & 0xFFFF
    return h


def get_short_path(path):
    k32.GetShortPathNameA.argtypes = [ctypes.c_char_p, ctypes.c_char_p, w.DWORD]
    k32.GetShortPathNameA.restype = w.DWORD
    buf = ctypes.create_string_buffer(260)
    if k32.GetShortPathNameA(path.encode("latin-1"), buf, 260):
        return buf.value.decode("latin-1")
    return path


def fold_path(s):
    h = 0
    for ch in s.encode("latin-1"):
        v = ch if ch < 128 else ch - 256
        h = (v * (v + h)) & 0xFFFF
    return h


def suffix_simple():
    return "%04x%04x" % (fold_user(USER_KEY), fold_master(MASTER_KEY))


def suffix_driveshare():
    short = get_short_path(APP_PATH)
    d = short.rsplit("\\", 1)[0] if "\\" in short else short
    return "%04x%0x.%03x" % (fold_user(USER_KEY), fold_master(MASTER_KEY), fold_path(d) & 0xFFF)


def tick():
    st = SYSTEMTIME()
    k32.GetLocalTime(ctypes.byref(st))
    return st.wMilliseconds // 10 + 100 * (st.wSecond + 60 * (st.wMinute + 60 * st.wHour))


# ============================================================================
# КОДЕК КЛЮЧЕЙ v5
# ============================================================================
M = 0x01E0E3
M_MASTER = 0x01FED3
PARAMS = {
    1:  (0x0329, 0x0829, M_MASTER),
    3:  (0x00E5, 0x042D, M),
    4:  (0x042D, 0x00E5, M),
    6:  (0x00E5, 0x042D, M),
    8:  (0x00E5, 0x042D, M),
    10: (0x00E5, 0x042D, M),
    12: (0x042D, 0x00E5, M),
}
MAGIC = [0xE4, 0x67, 0xF6, 0xA3]


def key_crc(key, key_type):
    if key_type in (2, 5, 7, 14):
        start, end = 0, len(key) - 2
    elif key_type in (3, 13):
        start, end = 0, len(key)
    elif key_type == 9:
        start, end = 3, len(key) - 2
    else:
        start, end = 1, len(key) - 2
    c = 0xFFFF
    for i in range(start, end):
        c ^= (reverse_bits(key[i]) << 8)
        for _ in range(8):
            c = ((c * 2) ^ 0x8005) & 0xFFFF if (c & 0x8000) else (c * 2) & 0xFFFF
    return (reverse_bits((c >> 8) & 0xFF) << 8) | reverse_bits(c & 0xFF)


def _xor_stage(data, forward):
    mk = list(MAGIC)
    out = bytearray(len(data))
    for i, ch in enumerate(data):
        v = (ch ^ mk[0] ^ mk[1] ^ mk[2] ^ mk[3]) & 0xFF
        out[i] = v
        mk[3] ^= mk[2]; mk[2] ^= mk[1]; mk[1] ^= mk[0]
        mk[0] ^= (v if forward else ch)
    return bytes(out)


def decrypt_v5(key, key_type):
    p, _e, m = PARAMS[key_type]
    klen = len(key)
    d1 = _xor_stage(key, forward=True)
    d2 = bytearray(klen)
    d2[0] = d1[0]
    seed = d1[0]
    idx = 1
    for i in range(1, klen, 2):
        cur = (d1[i] << 8) | d1[i + 1]
        if idx & seed:
            cur += 0x10000
        r = pow(cur, p, m)
        d2[i] = (r >> 8) & 0xFF
        d2[i + 1] = r & 0xFF
        idx *= 2
    return bytes(d2)


def encrypt_v5(plain, key_type):
    _d, p, m = PARAMS[key_type]
    klen = len(plain)
    e1 = bytearray(klen)
    seed = 0
    idx = 1
    for i in range(1, klen, 2):
        cur = (plain[i] << 8) | plain[i + 1]
        r = pow(cur, p, m)
        if r >= 0x10000:
            seed += idx
        e1[i] = (r >> 8) & 0xFF
        e1[i + 1] = r & 0xFF
        idx *= 2
    e1[0] = seed & 0xFF
    return _xor_stage(bytes(e1), forward=False)


# ============================================================================
# КЛЮЧИ: сборка / разбор
# ============================================================================
def fmt_key(s):
    """'F6E5B5BE...' (26 hex) -> 'F6E5 B5BE ... C3'."""
    h = re.sub(r"[^0-9A-Fa-f]", "", s)
    if len(h) == 26:
        return " ".join(h[i:i + 4] for i in range(0, 26, 4))
    return s.strip()


def read_site_key_file(path):
    try:
        raw = open(path, "rb").read().decode("latin-1").strip()
    except OSError:
        return None
    hx = re.sub(r"[^0-9A-Fa-f]", "", raw)
    if len(hx) == 26:
        return fmt_key(hx)
    return raw or None


def key_u2(sk_str):
    try:
        ct = bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", sk_str))
        p = decrypt_v5(ct, 6)
        return p[5] | (p[6] << 8) | (p[7] << 16) | (p[8] << 24)
    except Exception:
        return None


def build_key(site_code_id, ukh=0x7840, u2=0x00000000, count=127,
              network=True, duration=0x0000):
    """Собрать v5 Site Key: duration=0 -> unlimited, CRC по 12 байтам = 0."""
    p = bytearray(13)
    p[1] = site_code_id & 0x7F
    p[2] = ((-count) & 0xFF) if network else (count & 0xFF)
    p[3] = ukh & 0xFF
    p[4] = (ukh >> 8) & 0xFF
    p[5] = u2 & 0xFF
    p[6] = (u2 >> 8) & 0xFF
    p[7] = (u2 >> 16) & 0xFF
    p[8] = (u2 >> 24) & 0xFF
    p[9] = duration & 0xFF
    p[10] = (duration >> 8) & 0xFF
    c = key_crc(p, 6)
    p[11] = (c >> 8) & 0xFF
    p[12] = c & 0xFF
    return encrypt_v5(p, 6)


def current_key_fields():
    p = LICENSE_FILES[0]
    try:
        hx = open(p, "rb").read().decode("latin-1").strip().replace(" ", "")
        d = decrypt_v5(bytes.fromhex(hx), 6)
        return d[3] | (d[4] << 8), d[5] | (d[6] << 8) | (d[7] << 16) | (d[8] << 24), d[1] & 0x7F
    except Exception:
        return 0x7840, 0, None


# ============================================================================
# .glic: чтение, CRC32, GF(2)-подбор токена (на случай генерации .glic)
# ============================================================================
CRC_POLY = 0x9609A88E
CRC_TARGET_DEMO = 0x23AA94AB
GLIC_CRC_OFFSET = 0x1A3


def _crc_table(poly):
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ poly if c & 1 else c >> 1
        t.append(c & 0xFFFFFFFF)
    return t


_CRC_TABLE = _crc_table(CRC_POLY)


def crc32_glic(data):
    c = 0xFFFFFFFF
    for b in data:
        c = _CRC_TABLE[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


def tail_crc(data):
    return crc32_glic(data[GLIC_CRC_OFFSET:])


def bitreverse32(x):
    r = 0
    for _ in range(32):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r & 0xFFFFFFFF


class Glic(object):
    def __init__(self):
        self.header_lines = []
        self.site_key = ""
        self.license_type = ""
        self.format_version = 0
        self.fields = []
        self.trailer = []

    @property
    def token(self):
        for line in self.trailer:
            if line.strip():
                return line.strip()
        return ""


def parse_glic(path):
    raw = open(path, "rb").read()
    text = raw.decode("utf-16") if raw[:2] == b"\xff\xfe" else raw.decode("latin-1", "replace")
    lines = text.split("\r\n")
    lic = Glic()
    lic.header_lines = lines[:4]
    lic.site_key = lines[4].strip() if len(lines) > 4 else ""
    lic.license_type = lines[5].strip() if len(lines) > 5 else ""
    lic.format_version = int(lines[6].strip()) if len(lines) > 6 else 0
    i = 7
    while i < len(lines) and re.fullmatch(r"\s*\d+\s*", lines[i]):
        lic.fields.append(int(lines[i].strip()))
        i += 1
    lic.trailer = lines[i:]
    return lic


def generate_glic(lic):
    parts = [h + "\r\n" for h in lic.header_lines]
    parts.append(lic.site_key + "\r\n")
    parts.append(lic.license_type + "\r\n")
    parts.append(str(lic.format_version) + "\r\n")
    parts.extend(str(v) + "\r\n" for v in lic.fields)
    return ("".join(parts) + "\r\n".join(lic.trailer)).encode("latin-1")


def _gf2_solve(cols, d):
    piv = [None] * 32
    for k, val in enumerate(cols):
        mask = 1 << k
        while val:
            h = val.bit_length() - 1
            if piv[h] is None:
                piv[h] = (val, mask)
                break
            val ^= piv[h][0]
            mask ^= piv[h][1]
    dm = 0
    while d:
        h = d.bit_length() - 1
        if piv[h] is None:
            return None
        d ^= piv[h][0]
        dm ^= piv[h][1]
    return dm


def solve_token(lic, target, n=4, tries=4000):
    token = lic.token
    if len(token) != 20:
        return None, None
    ti = next((i for i, l in enumerate(lic.trailer) if l.strip()), None)
    if ti is None:
        return None, None
    base_prefix = token[:20 - n]
    printable = [chr(c) for c in range(0x21, 0x7F)]
    for attempt in range(tries):
        fixed = list(base_prefix)
        fixed[0] = printable[attempt % len(printable)]
        fixed[1] = printable[(attempt // len(printable)) % len(printable)]
        placeholder = "".join(fixed) + "A" * n
        lic.trailer[ti] = placeholder
        data = generate_glic(lic)
        var_off = data.find(placeholder.encode("latin-1")) + (20 - n)
        prefix = data[GLIC_CRC_OFFSET:var_off]
        suffix = data[var_off + n:]
        want_raw = target ^ 0xFFFFFFFF

        def F(bs):
            c = 0xFFFFFFFF
            for b in prefix + bs + suffix:
                c = _CRC_TABLE[(c ^ b) & 0xFF] ^ (c >> 8)
            return c

        f0 = F(b"\x00" * n)
        cols = []
        for i in range(n):
            for bit in range(8):
                bs = bytearray(n)
                bs[i] = 1 << bit
                cols.append(F(bytes(bs)) ^ f0)
        dm = _gf2_solve(cols, want_raw ^ f0)
        if dm is None:
            continue
        bs = bytes((dm >> (i * 8)) & 0xFF for i in range(n))
        if all(0x21 <= b <= 0x7E for b in bs):
            cand = "".join(fixed) + bs.decode("latin-1")
            lic.trailer[ti] = cand
            return cand, generate_glic(lic)
    return None, None


# ============================================================================
# CUSTOM INFO: 86 полей .glic -> 500 байт (раскладка GenLic32 sub_401610)
# ============================================================================
def build_custom_info(fields):
    v = bytearray(500)
    it = iter(fields)

    def nxt():
        return next(it, 0)

    def I(o, x):
        v[o:o + 4] = (x & 0xFFFFFFFF).to_bytes(4, "little")

    def W(o, x):
        v[o:o + 2] = (x & 0xFFFF).to_bytes(2, "little")

    def B(o, x):
        v[o] = x & 0xFF

    I(0, nxt()); I(4, nxt())
    W(8, nxt()); W(10, nxt()); W(12, nxt()); W(14, nxt())
    W(16, nxt()); W(18, nxt()); W(20, nxt()); W(22, nxt())
    for off in (24, 25, 26, 27, 28, 29, 30, 31):
        B(off, nxt())
    W(32, nxt()); W(34, nxt()); W(36, nxt()); W(38, nxt())
    B(40, nxt()); I(41, nxt()); I(45, nxt()); I(49, nxt()); I(53, nxt())
    W(57, nxt() & 0xFF); B(59, nxt()); B(60, nxt())
    W(61, nxt()); W(63, nxt()); W(65, nxt())
    B(71, nxt()); B(72, nxt()); B(73, nxt()); B(74, nxt()); B(75, nxt())
    B(76, nxt()); B(77, nxt()); B(78, nxt()); B(79, nxt())
    f43 = nxt()
    B(80, (f43 + 0x10 * nxt()) & 0xFF)
    B(81, nxt()); B(82, nxt()); B(83, nxt()); B(84, nxt()); B(85, nxt()); B(86, nxt())
    W(87, nxt()); W(89, nxt()); B(91, nxt()); B(92, nxt()); W(93, nxt()); W(95, nxt())
    B(97, nxt()); B(98, nxt()); B(99, nxt()); B(100, nxt()); B(101, nxt()); B(102, nxt())
    W(103, nxt()); B(105, nxt()); B(106, nxt()); W(107, nxt()); B(109, nxt())
    W(110, nxt()); W(112, nxt()); W(114, nxt()); W(116, nxt()); B(118, nxt()); B(119, nxt())
    W(120, nxt()); W(122, nxt()); W(124, nxt()); W(126, nxt())
    B(128, nxt()); W(129, nxt()); B(131, nxt())
    W(133, nxt()); W(135, nxt()); W(137, nxt()); W(139, nxt()); W(141, nxt()); W(143, nxt())
    return bytes(v)


# ============================================================================
# MAILSLOT / NGN
# ============================================================================
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

k32.CreateMailslotA.argtypes = [ctypes.c_char_p, w.DWORD, w.DWORD, ctypes.c_void_p]
k32.CreateMailslotA.restype = w.HANDLE
k32.CreateFileA.argtypes = [ctypes.c_char_p, w.DWORD, w.DWORD, ctypes.c_void_p,
                            w.DWORD, w.DWORD, ctypes.c_void_p]
k32.CreateFileA.restype = w.HANDLE
k32.WriteFile.argtypes = [w.HANDLE, ctypes.c_void_p, w.DWORD,
                          ctypes.POINTER(w.DWORD), ctypes.c_void_p]
k32.WriteFile.restype = w.BOOL
k32.ReadFile.argtypes = [w.HANDLE, ctypes.c_void_p, w.DWORD,
                         ctypes.POINTER(w.DWORD), ctypes.c_void_p]
k32.ReadFile.restype = w.BOOL
k32.GetMailslotInfo.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD), ctypes.POINTER(w.DWORD),
                                ctypes.POINTER(w.DWORD), ctypes.POINTER(w.DWORD)]
k32.GetMailslotInfo.restype = w.BOOL
k32.CloseHandle.argtypes = [w.HANDLE]
k32.CloseHandle.restype = w.BOOL
k32.GetCurrentProcessId.restype = w.DWORD
k32.GetLocalTime.argtypes = [ctypes.c_void_p]


class SYSTEMTIME(ctypes.Structure):
    _fields_ = [("wYear", w.WORD), ("wMonth", w.WORD), ("wDayOfWeek", w.WORD),
                ("wDay", w.WORD), ("wHour", w.WORD), ("wMinute", w.WORD),
                ("wSecond", w.WORD), ("wMilliseconds", w.WORD)]


def ms_create(name):
    h = k32.CreateMailslotA(name.encode("ascii"), 0, 0, None)
    if h == INVALID_HANDLE_VALUE:
        raise OSError("CreateMailslotA(%s) err=%d" % (name, ctypes.get_last_error()))
    return h


def ms_write(path, data):
    h = k32.CreateFileA(path.encode("ascii"), GENERIC_WRITE, FILE_SHARE_READ,
                        None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    if h == INVALID_HANDLE_VALUE:
        return False
    written = w.DWORD(0)
    buf = ctypes.create_string_buffer(bytes(data), len(data))
    ok = k32.WriteFile(h, buf, len(data), ctypes.byref(written), None)
    k32.CloseHandle(h)
    return bool(ok)


def ms_read(h, timeout_ms):
    deadline = time.time() + timeout_ms / 1000.0
    while time.time() < deadline:
        next_size = w.DWORD(0)
        msg_count = w.DWORD(0)
        k32.GetMailslotInfo(h, None, ctypes.byref(next_size), ctypes.byref(msg_count), None)
        if msg_count.value == 0:
            time.sleep(0.02)
            continue
        size = next_size.value
        if size == 0:
            time.sleep(0.02)
            continue
        buf = ctypes.create_string_buffer(size)
        read = w.DWORD(0)
        if k32.ReadFile(h, buf, size, ctypes.byref(read), None):
            return buf.raw[:read.value]
        return None
    return None


class CrypKeyClient(object):
    def __init__(self, log=print, force_suffix=None):
        self.log = log
        self.client_h = None
        self.perclient = None
        self.force_suffix = force_suffix
        self.computername = os.environ.get("COMPUTERNAME", "")
        self.domain = os.environ.get("USERDOMAIN", self.computername)
        self.username = os.environ.get("USERNAME", "")
        self.counter = (k32.GetCurrentProcessId() * max(tick(), 1)) & 0x7FFFFFFF

    def _next_id(self):
        self.counter += 1
        return self.counter & 0x7FFFFFFF

    @staticmethod
    def _put(buf, off, text, maxlen):
        try:
            raw = text.encode("mbcs", "replace")
        except Exception:
            raw = text.encode("ascii", "replace")
        raw = raw[:maxlen - 1]
        buf[off:off + len(raw)] = raw

    def _build_msg(self, mtype, path):
        msg = bytearray(0x150)
        struct.pack_into("<h", msg, 4, 1)
        struct.pack_into("<h", msg, 6, mtype)
        struct.pack_into("<i", msg, 8, 0)
        self._put(msg, 0x10, self.domain, 40)
        self._put(msg, 0x38, self.username, 40)
        self._put(msg, 0x60, self.computername, 40)
        self._put(msg, 0x88, path, 200)
        return msg

    def connect(self):
        cid = "%08x" % ((k32.GetCurrentProcessId() * max(tick(), 1)) & 0xFFFFFFFF)
        self.client_slot = "\\\\.\\mailslot\\" + cid
        self.log("[*] client slot : %s" % self.client_slot)
        self.client_h = ms_create(self.client_slot)
        while ms_read(self.client_h, 100) is not None:
            pass
        candidates = [suffix_simple(), suffix_driveshare()]
        if self.force_suffix:
            candidates = [self.force_suffix]
        self.log("[*] suffix candidates: %s" % ", ".join(candidates))
        reply = None
        for attempt in range(4):
            for sfx in candidates:
                server_slot = "\\\\.\\mailslot\\" + sfx
                self.log("[*] try server slot: %s (attempt %d)" % (server_slot, attempt + 1))
                q = self._build_msg(4, self.client_slot)
                struct.pack_into("<i", q, 0, self._next_id())
                if not ms_write(server_slot, bytes(q)):
                    self.log("[!] query write failed (server not running?)")
                    continue
                reply = ms_read(self.client_h, 2000)
                if reply is not None:
                    self.log("[*] query reply %d bytes via %s" % (len(reply), sfx))
                    break
            if reply is not None:
                break
            time.sleep(2.0)
        if reply is None:
            raise OSError("no query reply from any suffix (server not running?)")
        srv_path = reply[0x88:0x88 + 200].split(b"\x00")[0].decode("latin-1")
        self.log("[*] server path: %s" % srv_path)
        machine = srv_path
        for _ in range(2):
            i = machine.rfind("\\")
            if i < 0:
                break
            machine = machine[:i]
        c = self._build_msg(2, self.client_slot)
        struct.pack_into("<i", c, 0, self._next_id())
        if not ms_write(srv_path, bytes(c)):
            raise OSError("connect send failed")
        creply = ms_read(self.client_h, 10000)
        if creply is None:
            raise OSError("no connect reply")
        if struct.unpack_from("<i", creply, 8)[0] == 0:
            raise OSError("connect rejected")
        pid = creply[0x88:0x88 + 200].split(b"\x00")[0].decode("latin-1")
        self.perclient = machine + "\\mailslot\\" + pid
        self.log("[*] per-client : %s" % self.perclient)

    def send_block(self, payload):
        total = len(payload)
        offset = 0
        index = 0
        while offset < total:
            chunk = min(CHUNK, total - offset)
            data = obf(payload[offset:offset + chunk], decrypt=False)
            packet = bytearray(PKT)
            struct.pack_into("<i", packet, 8, index)
            struct.pack_into("<i", packet, 0xC, chunk)
            struct.pack_into("<i", packet, 0x10, total)
            packet[0x14:0x14 + chunk] = data
            for _attempt in range(3):
                msg_id = self._next_id()
                struct.pack_into("<i", packet, 0, msg_id)
                if not ms_write(self.perclient, bytes(packet)):
                    raise OSError("send packet failed")
                ack = ms_read(self.client_h, 5000)
                if ack is None or len(ack) < ACK:
                    continue
                if struct.unpack_from("<i", ack, 4)[0] != msg_id:
                    continue
                if struct.unpack_from("<i", ack, 8)[0] == 0:
                    break
                if struct.unpack_from("<i", ack, 8)[0] == -2:
                    continue
                raise OSError("send packet status=%d" % struct.unpack_from("<i", ack, 8)[0])
            offset += chunk
            index += 1

    def recv_block(self):
        buf = bytearray()
        total = None
        while True:
            pkt = ms_read(self.client_h, 30000)
            if pkt is None:
                raise OSError("recv timeout")
            chunk = struct.unpack_from("<i", pkt, 0xC)[0]
            total = struct.unpack_from("<i", pkt, 0x10)[0]
            pkt_id = struct.unpack_from("<i", pkt, 0)[0]
            ack = bytearray(ACK)
            struct.pack_into("<i", ack, 0, self._next_id())
            struct.pack_into("<i", ack, 4, pkt_id)
            struct.pack_into("<i", ack, 8, 0)
            ms_write(self.perclient, bytes(ack))
            buf += obf(pkt[0x14:0x14 + chunk], decrypt=True)
            if total is not None and len(buf) >= total:
                break
        return bytes(buf[:total]) if total else bytes(buf)

    def execute(self, block):
        req_crc = crc16(block[:-2]) if len(block) >= 2 else crc16(block)
        payload = hex_encode(block) + b"\x00"
        self.send_block(payload)
        resp = self.recv_block().split(b"\x00")[0]
        resp_block = hex_decode(resp)
        offset = ((req_crc & 7) + len(resp_block) - 0xE) if resp_block else 0
        result = struct.unpack_from("<i", resp_block, offset)[0] \
            if 0 <= offset <= len(resp_block) - 4 else None
        return result, resp_block

    def init_crypkey(self):
        payload = (APP_PATH.encode("latin-1") + b"\x00"
                   + USER_KEY.encode("latin-1") + b"\x00"
                   + MASTER_KEY.encode("latin-1") + b"\x00")
        payload += struct.pack("<II", 0, 0)
        payload += struct.pack("<I", 0x452F)
        payload += struct.pack("<I", 8)
        data = struct.pack("<II", 2, 0) + payload
        v15 = ((len(data) + 0x12) + 1) & ~1
        block = data + b"\x00" * ((v15 - 2) - len(data))
        block += struct.pack("<H", crc16(block))
        return self.execute(bytes(block))

    def get_site_code(self):
        block = bytearray(0x16)
        struct.pack_into("<I", block, 0, 2)
        struct.pack_into("<I", block, 4, 3)
        struct.pack_into("<H", block, 0x14, crc16(block[:0x14]))
        return self.execute(bytes(block))

    def get_authorization(self, param=0):
        block = bytearray(0x1A)
        struct.pack_into("<I", block, 0, 2)
        struct.pack_into("<I", block, 4, 1)
        struct.pack_into("<i", block, 8, param)
        struct.pack_into("<H", block, 0x18, crc16(block[:0x18]))
        r, resp = self.execute(bytes(block))
        auth = struct.unpack_from("<I", resp, 2)[0] if len(resp) >= 6 else None
        return r, auth, resp

    def ready_to_try(self, level, days, version, copies=0xFFFFFFFF):
        block = bytearray(0x2A)
        struct.pack_into("<I", block, 0, 2)
        struct.pack_into("<I", block, 4, 0x20)
        struct.pack_into("<i", block, 8, level)
        struct.pack_into("<i", block, 0xC, days)
        struct.pack_into("<i", block, 0x10, version)
        struct.pack_into("<i", block, 0x14, 1)
        struct.pack_into("<I", block, 0x18, copies & 0xFFFFFFFF)
        struct.pack_into("<H", block, 0x28, crc16(block[:0x28]))
        return self.execute(bytes(block))

    def save_site_key(self, sitekey):
        raw = sitekey.encode("ascii", "replace")
        a1 = len(raw) + 1 + 8
        total = (a1 + 0xE + 1) & ~1
        block = bytearray(total)
        struct.pack_into("<I", block, 0, 2)
        struct.pack_into("<I", block, 4, 4)
        block[8:8 + len(raw)] = raw
        struct.pack_into("<H", block, total - 2, crc16(block[:total - 2]))
        return self.execute(bytes(block))

    def get_custom_info(self):
        block = bytearray(0x16)
        struct.pack_into("<I", block, 0, 2)
        struct.pack_into("<I", block, 4, 0x23)
        struct.pack_into("<H", block, 0x14, crc16(block[:0x14]))
        r, resp = self.execute(bytes(block))
        return r, bytes(resp[:0x1F4]), resp

    def set_custom_info(self, data):
        payload = bytes(data)[:500]
        payload = payload + b"\x00" * (500 - len(payload))
        total = (0x1FC + 0xE + 1) & ~1
        block = bytearray(total)
        struct.pack_into("<I", block, 0, 2)
        struct.pack_into("<I", block, 4, 0x24)
        block[8:8 + 500] = payload
        struct.pack_into("<H", block, total - 2, crc16(block[:total - 2]))
        return self.execute(bytes(block))


def start_server():
    cmd = '"%s" %s %s "%s"' % (NGN_PATH, USER_KEY, MASTER_KEY, APP_PATH)
    print("[*] start server: %s" % NGN_PATH)
    try:
        subprocess.Popen(cmd, creationflags=0x00000008)
    except OSError as e:
        print("[!] start server failed: %s" % e)
    time.sleep(2.0)


def dump_license_files(log=print):
    for path in LICENSE_FILES:
        try:
            data = open(path, "rb").read()
        except (OSError, IOError) as e:
            log("[!] %s: %s" % (path, e))
            continue
        log("[+] %s (%d bytes)" % (path, len(data)))
        log("    str: %r%s" % (data[:120].decode("latin-1", "replace"),
                               " ..." if len(data) > 120 else ""))


# ============================================================================
# УСТАНОВКА КЛЮЧА (перебор siteCodeId)
# ============================================================================
def install_key(cli, u2, count=127, network=True, duration=0,
                no_getsitecode=False, log=print):
    ukh, _u2cur, id_cur = current_key_fields()
    log("[*] ukh=0x%04X u2(цель)=0x%08X текущий siteCodeId=%s" % (ukh, u2, id_cur))
    time_id = int(time.time()) & 0x7F
    log("[*] локальная догадка id = time&0x7F = 0x%02X" % time_id)
    winner = None
    for label, sid in (("time", time_id), ("текущий", id_cur)):
        if sid is None:
            continue
        key = build_key(sid, ukh=ukh, u2=u2, count=count,
                        network=network, duration=duration).hex().upper()
        r, _ = cli.save_site_key(key)
        log("    [%s] id=0x%02X -> SaveSiteKey result=%s" % (label, sid, r))
        if r == 0:
            winner = (sid, key)
            break
    order = []
    if not winner and not no_getsitecode:
        r, scblk = cli.get_site_code()
        log("[+] Site Code: %s" % scblk.decode("latin-1", "replace").strip())
        tried = {time_id, id_cur}
        order = [i for i in range(128) if i not in tried]
    for n, sid in enumerate(order):
        key = build_key(sid, ukh=ukh, u2=u2, count=count,
                        network=network, duration=duration).hex().upper()
        r, _ = cli.save_site_key(key)
        log("    [%3d] id=0x%02X -> SaveSiteKey result=%s" % (n, sid, r))
        if r == 0:
            winner = (sid, key)
            break
    if winner:
        log("[+] ПРИНЯТ ключ: id=0x%02X  %s" % winner)
    return winner


# ============================================================================
# MAIN
# ============================================================================
GLIC_CANDIDATES = [
    r"C:\ProgramData\ICONICS\demo.glic",
    r"C:\Analiz\genesis\demo.glic",
    "demo.glic",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "FromPC", "ICONICS", "demo.glic"),
]


def find_glic(explicit):
    if explicit and os.path.isfile(explicit):
        return explicit
    for p in GLIC_CANDIDATES:
        if os.path.isfile(p):
            return p
    return None


def apply_fields(fields, overrides, log=print):
    for spec in overrides:
        m = re.fullmatch(r"(\d+)=(\d+)", spec)
        if not m:
            log("[!] плохой --field %r (нужно N=V)" % spec)
            continue
        n, v = int(m.group(1)), int(m.group(2))
        if 0 <= n < len(fields):
            log("[+] поле [%d]: %d -> %d" % (n, fields[n], v))
            fields[n] = v
        else:
            log("[!] поле [%d] вне диапазона 0..%d" % (n, len(fields) - 1))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--level", default="38208")
    ap.add_argument("--options", default="0x2FFC")
    ap.add_argument("--count", type=int, default=127)
    ap.add_argument("--network", action="store_true", default=True)
    ap.add_argument("--no-network", dest="network", action="store_false")
    ap.add_argument("--days", type=int, default=0, help="0 = unlimited")
    ap.add_argument("--glic", default=None)
    ap.add_argument("--field", action="append", default=[], help="N=V (можно много)")
    ap.add_argument("--client-units", type=int, default=None, help="= поле 24")
    ap.add_argument("--product-limit", type=int, default=None, help="= поле 23")
    ap.add_argument("--pnum", default="5346")
    ap.add_argument("--sitekeytxt", default=DEFAULT_SITEKEYTXT)
    ap.add_argument("--no-start", action="store_true")
    ap.add_argument("--suffix", default=None)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--skip-key", action="store_true")
    ap.add_argument("--skip-custom", action="store_true")
    ap.add_argument("--skip-sitekeytxt", action="store_true")
    ap.add_argument("--list-fields", action="store_true")
    a = ap.parse_args()

    level = int(a.level, 0)
    options = int(a.options, 0)
    u2 = (level & 0xFFFF) | ((options & 0xFFFF) << 16)
    duration = 0 if a.days == 0 else ((a.days & 0x7FFF) | 0x8000)
    glic = find_glic(a.glic)

    if a.list_fields:
        if not glic:
            print("[!] .glic не найден")
            return
        lic = parse_glic(glic)
        print("[i] %s - %d полей:" % (glic, len(lic.fields)))
        for i, v in enumerate(lic.fields):
            tag = {23: "product-limit", 24: "ClientUnits",
                   25: "options-mask", 27: "flag"}.get(i, "")
            print("    %2d = %-10d %s" % (i, v, tag))
        return

    if a.dry_run:
        print("[dry-run] u2=0x%08X duration=0x%04X .glic=%s" % (u2, duration, glic))
        return

    if not a.no_start:
        start_server()
    cli = CrypKeyClient(force_suffix=a.suffix)
    cli.connect()
    print("[+] InitCrypkey result=%s" % cli.init_crypkey()[0])

    r, scblk = cli.get_site_code()
    print("[+] Site Code: %s" % scblk.decode("latin-1", "replace").strip())

    if not a.skip_key:
        if not install_key(cli, u2, count=a.count, network=a.network,
                           duration=duration):
            print("[!] ключ не установлен; если нужно - активируй Emergency License и повтори")

    if not a.skip_custom:
        if not glic:
            print("[!] .glic не найден - entitlement пропущен")
        else:
            lic = parse_glic(glic)
            apply_fields(lic.fields, a.field)
            if a.client_units is not None:
                lic.fields[24] = a.client_units
                print("[+] field[24] (Client Units) = %d" % a.client_units)
            if a.product_limit is not None:
                lic.fields[23] = a.product_limit
                print("[+] field[23] (product limit) = %d" % a.product_limit)
            blob = build_custom_info(lic.fields)
            r, _ = cli.set_custom_info(blob)
            print("[+] SetCustomInfoBytes result=%s (%d байт)" % (r, len(blob)))

    if not a.skip_sitekeytxt:
        key = read_site_key_file(LICENSE_FILES[0])
        if key:
            data = ("\r\n".join([key, a.pnum]) + "\r\n").encode("latin-1")
            os.makedirs(os.path.dirname(a.sitekeytxt), exist_ok=True)
            open(a.sitekeytxt, "wb").write(data)
            print("[+] %s: %s | %s" % (a.sitekeytxt, key, a.pnum))

    print("[*] Готово. GenLic32 -> Actions -> View License -> Refresh.")


if __name__ == "__main__":
    main()
