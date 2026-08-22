#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ipsearch - i-PRO 同軸-LANコンバーターの IP アドレスを L2 スイープで探し出す。

対象機種: WJ-PR204UX / WJ-PR201UX / WJ-PC200UX

これらの機種には工場出荷時への初期化(リセット)手段が無い。設定画面(Option)で
IP アドレスを変更したあとアドレスを忘れると Web UI に到達できなくなる。

本ツールは機器のネットワーク端子に直結した Mac から ARP スイープを行う。ARP は
L2 のプロトコルなので、こちら側の IP 設定と相手の IP 設定が噛み合っていなくても
応答が返る。応答したホストに対して HTTP を叩き、認証レルム(WJ-PR204 等)で
対象機器を同定する。

macOS 専用 (BPF /dev/bpfN を直接使用)。標準ライブラリのみ。sudo 必須。
"""

import argparse
import ctypes
import errno
import fcntl
import ipaddress
import json
import os
import re
import select
import signal
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# BPF (macOS /dev/bpfN)
# ---------------------------------------------------------------------------

BIOCGBLEN = 0x40044266
BIOCSBLEN = 0xC0044266
BIOCSETF = 0x80104267
BIOCFLUSH = 0x20004268
BIOCPROMISC = 0x20004269
BIOCSETIF = 0x8020426C
BIOCSRTIMEOUT = 0x8010426D
BIOCIMMEDIATE = 0x80044270
BIOCSHDRCMPLT = 0x80044275
BIOCSSEESENT = 0x80044277

# BPF 命令: ldh [12] して ethertype が ARP(0x0806) か IPv4(0x0800) のものだけ通す
BPF_FILTER_ARP_IP = [
    (0x28, 0, 0, 12),
    (0x15, 1, 0, 0x0806),
    (0x15, 0, 1, 0x0800),
    (0x06, 0, 0, 262144),
    (0x06, 0, 0, 0),
]


class Bpf:
    """BPF デバイスを 1 本掴んで、生イーサネットフレームの送受信を行う。"""

    def __init__(self, ifname, promisc=True, bufsize=4 * 1024 * 1024,
                 read_timeout_ms=200, bpf_filter=None):
        self.ifname = ifname
        self.fd = self._open_device()
        try:
            # バッファ長はインターフェースに bind する前に決める必要がある
            buf = struct.pack("@I", bufsize)
            buf = fcntl.ioctl(self.fd, BIOCSBLEN, buf, True)
            self.blen = struct.unpack("@I", buf)[0]

            ifreq = ifname.encode().ljust(16, b"\0") + b"\0" * 16
            fcntl.ioctl(self.fd, BIOCSETIF, ifreq)

            fcntl.ioctl(self.fd, BIOCIMMEDIATE, struct.pack("@I", 1))
            # 自分で組んだイーサヘッダ(送信元 MAC 含む)をそのまま使う
            fcntl.ioctl(self.fd, BIOCSHDRCMPLT, struct.pack("@I", 1))
            # 自分が送ったフレームは受信側に回さない
            fcntl.ioctl(self.fd, BIOCSSEESENT, struct.pack("@I", 0))
            if promisc:
                fcntl.ioctl(self.fd, BIOCPROMISC)
            fcntl.ioctl(self.fd, BIOCSRTIMEOUT,
                        struct.pack("@qi4x", read_timeout_ms // 1000,
                                    (read_timeout_ms % 1000) * 1000))
            if bpf_filter:
                self._set_filter(bpf_filter)
            fcntl.ioctl(self.fd, BIOCFLUSH)
        except Exception:
            os.close(self.fd)
            raise

    @staticmethod
    def _open_device():
        saw_eacces = False
        for i in range(256):
            try:
                return os.open("/dev/bpf%d" % i, os.O_RDWR)
            except OSError as e:
                if e.errno == errno.EACCES:
                    saw_eacces = True
                    continue
                if e.errno in (errno.EBUSY, errno.ENOENT, errno.ENXIO):
                    continue
                raise
        if saw_eacces:
            raise PermissionError(
                "/dev/bpf* を開けません。sudo で実行してください。")
        raise OSError("空いている /dev/bpf* がありません。")

    def _set_filter(self, insns):
        blob = b"".join(struct.pack("@HBBI", *i) for i in insns)
        self._filter_buf = ctypes.create_string_buffer(blob, len(blob))
        prog = struct.pack("@IQ", len(insns),
                           ctypes.addressof(self._filter_buf))
        fcntl.ioctl(self.fd, BIOCSETF, prog)

    def send(self, frame):
        """フレームを 1 本送る。カーネルバッファ溢れは待って再送する。"""
        while True:
            try:
                os.write(self.fd, frame)
                return
            except OSError as e:
                if e.errno in (errno.ENOBUFS, errno.EAGAIN):
                    time.sleep(0.001)
                    continue
                raise

    def read_frames(self, timeout=0.2):
        """受信済みフレームを list で返す。タイムアウト時は空 list。"""
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return []
        try:
            buf = os.read(self.fd, self.blen)
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EINTR):
                return []
            raise
        return list(self._parse(buf))

    @staticmethod
    def _parse(buf):
        off, n = 0, len(buf)
        while off + 18 <= n:
            caplen, datalen = struct.unpack_from("@II", buf, off + 8)
            hdrlen = struct.unpack_from("@H", buf, off + 16)[0]
            start = off + hdrlen
            end = start + caplen
            if hdrlen == 0 or end > n:
                return
            yield buf[start:end]
            off += (hdrlen + caplen + 3) & ~3

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


# ---------------------------------------------------------------------------
# インターフェース情報 (ifconfig をパースする)
# ---------------------------------------------------------------------------

def list_interfaces():
    out = subprocess.run(["ifconfig", "-a"], capture_output=True,
                         text=True).stdout
    ifaces, cur = [], None
    for line in out.splitlines():
        m = re.match(r"^([A-Za-z0-9_.]+):\s+flags=\d+<([^>]*)>", line)
        if m:
            cur = {"name": m.group(1), "flags": m.group(2).split(","),
                   "mac": None, "inet": [], "status": None}
            ifaces.append(cur)
            continue
        if cur is None:
            continue
        m = re.search(r"\bether\s+([0-9a-fA-F:]{17})", line)
        if m:
            cur["mac"] = m.group(1).lower()
        m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+)",
                      line)
        if m:
            cur["inet"].append((m.group(1), int(m.group(2), 16)))
        m = re.search(r"\bstatus:\s+(\w+)", line)
        if m:
            cur["status"] = m.group(1)
    return ifaces


def get_interface(name):
    for i in list_interfaces():
        if i["name"] == name:
            return i
    return None


def default_route_iface():
    out = subprocess.run(["route", "-n", "get", "default"],
                         capture_output=True, text=True).stdout
    m = re.search(r"interface:\s+(\S+)", out)
    return m.group(1) if m else None


def candidate_interfaces():
    """物理っぽくて link が up しているインターフェースを返す。"""
    res = []
    for i in list_interfaces():
        if i["mac"] is None:
            continue
        if not re.match(r"^(en|eth)\d+$", i["name"]):
            continue
        res.append(i)
    return res


def mac_to_bytes(mac):
    return bytes(int(x, 16) for x in mac.split(":"))


def bytes_to_mac(b):
    return ":".join("%02x" % x for x in b)


# ---------------------------------------------------------------------------
# ARP スイープ
# ---------------------------------------------------------------------------

ETH_BROADCAST = b"\xff" * 6
ARP_HDR = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)  # request


def build_arp_request(src_mac, spa, tpa):
    return (ETH_BROADCAST + src_mac + b"\x08\x06"
            + ARP_HDR + src_mac + spa + b"\x00" * 6 + tpa)


def spa_for(target_int, mode, fixed):
    """送信元 IP を決める。

    peer : ターゲットと同じ /24 のアドレスを名乗る。相手のスタックが
           サブネット外からの ARP に応答しない実装でも確実に返る。
    probe: 0.0.0.0 (RFC 5227 の ARP probe)。相手の ARP テーブルを汚さない。
    """
    if mode == "probe":
        return b"\x00\x00\x00\x00"
    if mode == "fixed":
        return fixed
    base = target_int & 0xFFFFFF00
    last = target_int & 0xFF
    src = base | (2 if last == 1 else 1)
    return struct.pack("!I", src)


class ArpSweeper:
    def __init__(self, bpf, src_mac, spa_mode="peer", fixed_spa=None,
                 pps=20000, retries=2, mac_filter=None, quiet=False):
        self.bpf = bpf
        self.src_mac = src_mac
        self.spa_mode = spa_mode
        self.fixed_spa = fixed_spa
        self.pps = max(1, pps)
        self.retries = max(1, retries)
        self.mac_filter = mac_filter.lower() if mac_filter else None
        self.quiet = quiet
        self.found = {}          # ip(str) -> {"mac":..., "how":...}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._reader = None

    # -- 受信側 ------------------------------------------------------------
    def _record(self, ip, mac, how):
        if self.mac_filter and mac != self.mac_filter:
            return
        with self._lock:
            if ip in self.found:
                return
            self.found[ip] = {"mac": mac, "how": how}
        if not self.quiet:
            sys.stderr.write("\r\033[K")
            print("  [+] %-15s  %s  (%s)" % (ip, mac, how), flush=True)

    def _handle(self, frame):
        if len(frame) < 14:
            return
        etype = struct.unpack_from("!H", frame, 12)[0]
        src_mac = bytes_to_mac(frame[6:12])
        if etype == 0x0806 and len(frame) >= 42:
            op = struct.unpack_from("!H", frame, 20)[0]
            sha = bytes_to_mac(frame[22:28])
            spa = ".".join(str(b) for b in frame[28:32])
            if spa != "0.0.0.0":
                self._record(spa, sha, "ARP reply" if op == 2 else "ARP request")
        elif etype == 0x0800 and len(frame) >= 34:
            src = ".".join(str(b) for b in frame[26:30])
            if src != "0.0.0.0":
                self._record(src, src_mac, "IPv4 traffic")

    def _read_loop(self):
        while not self._stop.is_set():
            for f in self.bpf.read_frames(timeout=0.2):
                self._handle(f)

    def start_reader(self):
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def stop_reader(self, settle=2.0):
        """応答を settle 秒待ってから受信スレッドを確実に畳む。

        join を待たずに Bpf.close() すると、受信スレッドが閉じた fd を
        select/read してしまうので、必ずここを通してから close すること。
        """
        deadline = time.monotonic() + settle
        while time.monotonic() < deadline:
            time.sleep(0.1)
        self._stop.set()
        if self._reader:
            self._reader.join(timeout=3.0)
            self._reader = None

    # -- 送信側 ------------------------------------------------------------
    def sweep(self, networks):
        total = sum(net.num_addresses for net in networks) * self.retries
        sent = 0
        started = time.monotonic()
        chunk = max(1, self.pps // 100)
        last_report = 0.0
        try:
            for _ in range(self.retries):
                for net in networks:
                    lo = int(net.network_address)
                    hi = int(net.broadcast_address)
                    for ip_int in range(lo, hi + 1):
                        tpa = struct.pack("!I", ip_int)
                        spa = spa_for(ip_int, self.spa_mode, self.fixed_spa)
                        self.bpf.send(build_arp_request(self.src_mac, spa, tpa))
                        sent += 1
                        if sent % chunk == 0:
                            expected = started + sent / self.pps
                            now = time.monotonic()
                            if now < expected:
                                time.sleep(expected - now)
                            if not self.quiet and now - last_report > 0.5:
                                last_report = now
                                self._progress(sent, total, now - started)
        except KeyboardInterrupt:
            sys.stderr.write("\r\033[K")
            print("  [!] 中断しました (ここまでの結果を表示します)")
        if not self.quiet:
            sys.stderr.write("\r\033[K")
        return sent

    def _progress(self, sent, total, elapsed):
        rate = sent / elapsed if elapsed > 0 else 0
        remain = (total - sent) / rate if rate > 0 else 0
        sys.stderr.write(
            "\r\033[K  %6.2f%%  %d/%d  %.0f pps  残り %s  発見 %d 件"
            % (100.0 * sent / total, sent, total, rate,
               fmt_duration(remain), len(self.found)))
        sys.stderr.flush()


def fmt_duration(sec):
    sec = int(sec)
    if sec < 60:
        return "%d秒" % sec
    if sec < 3600:
        return "%d分%02d秒" % (sec // 60, sec % 60)
    return "%d時間%02d分" % (sec // 3600, (sec % 3600) // 60)


# ---------------------------------------------------------------------------
# HTTP による機器同定
# ---------------------------------------------------------------------------

TARGET_MODELS = ("WJ-PR204", "WJ-PR201", "WJ-PC200")
DEFAULT_CREDS = [("WJ-PR204", "999999"),
                 ("WJ-PR201", "999999"),
                 ("WJ-PC200", "999999")]


def http_fetch(url, timeout, user=None, password=None):
    """(status, headers, body_text) を返す。到達不能なら None。"""
    # 直結ポート宛なので、システムのプロキシ設定は必ず無効化する
    handlers = [urllib.request.ProxyHandler({})]
    if user is not None:
        mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, url, user, password)
        handlers += [urllib.request.HTTPBasicAuthHandler(mgr),
                     urllib.request.HTTPDigestAuthHandler(mgr)]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": "ipsearch/1.0"})
    try:
        r = opener.open(req, timeout=timeout)
        return r.status, r.headers, r.read(8192).decode("latin-1")
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read(8192).decode("latin-1")
    except Exception:
        return None


def identify(ip, port=80, timeout=3.0, creds=None, try_creds="model"):
    """1 ホストを HTTP で叩いて機種を判定する。

    try_creds="model" のときは、レルム等で対象機種と判定できたホストにしか
    既定パスワードを送らない。共有ネットワークに繋がっていた場合に、無関係な
    機器へ認証を試行してしまうのを避けるため。
    """
    url = "http://%s:%d/" % (ip, port) if port != 80 else "http://%s/" % ip
    res = http_fetch(url, timeout)
    if res is None:
        return None
    status, headers, body = res
    info = {"ip": ip, "port": port, "http_status": status,
            "server": headers.get("Server"), "realm": None,
            "model": None, "authenticated": False, "detail": {}}

    wa = headers.get("WWW-Authenticate") or ""
    m = re.search(r'realm\s*=\s*"([^"]*)"', wa, re.I)
    if m:
        info["realm"] = m.group(1)

    haystack = "%s %s %s" % (info["realm"] or "", headers.get("Server") or "",
                             body)
    for model in TARGET_MODELS:
        if model in haystack:
            info["model"] = model
            break

    if status == 401 and (try_creds == "all" or info["model"]):
        for user, pw in (creds or DEFAULT_CREDS):
            res2 = http_fetch(url, timeout, user, pw)
            if res2 and res2[0] == 200:
                info["authenticated"] = True
                info["creds"] = "%s / %s" % (user, pw)
                body = res2[2]
                for model in TARGET_MODELS:
                    if model in body:
                        info["model"] = model
                break
    elif status == 200:
        info["authenticated"] = True

    info["detail"] = scrape_status(body)
    return info


def scrape_status(body):
    """設定画面の HTML から拾えるものを拾う (取れなくても致命的ではない)。"""
    text = re.sub(r"<[^>]+>", " ", body)
    text = re.sub(r"\s+", " ", text)
    out = {}
    for label in ("Boot version", "Firmware version"):
        m = re.search(re.escape(label) + r"\s*:?\s*([\w.\-]+)", text, re.I)
        if m:
            out[label] = m.group(1)
    m = re.search(r"([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}", text)
    if m:
        out["MAC address"] = m.group(0)
    m = re.search(r"Operation mode\s*:?\s*(Master|Terminal)", text, re.I)
    if m:
        out["Operation mode"] = m.group(1)
    return out


# ---------------------------------------------------------------------------
# 一時的な IP エイリアス (見つけた IP に HTTP で届くようにする)
# ---------------------------------------------------------------------------

class TempAlias:
    """ターゲットと同じ /24 の IP をインターフェースに一時的に生やす。"""

    def __init__(self, ifname, target_ip, enabled=True):
        self.ifname = ifname
        self.target = target_ip
        self.enabled = enabled
        self.addr = None

    def _already_reachable(self):
        t = ipaddress.IPv4Address(self.target)
        for i in list_interfaces():
            for addr, mask in i["inet"]:
                try:
                    net = ipaddress.IPv4Network(
                        "%s/%s" % (addr, ipaddress.IPv4Address(mask)),
                        strict=False)
                except ValueError:
                    continue
                if t in net:
                    return True
        return False

    def needs_root(self):
        return self.enabled and bool(self.ifname) and not self._already_reachable()

    def __enter__(self):
        if not self.needs_root():
            return self
        t = int(ipaddress.IPv4Address(self.target))
        base = t & 0xFFFFFF00
        host = base | (0xFE if (t & 0xFF) != 0xFE else 0xFD)
        addr = str(ipaddress.IPv4Address(host))
        r = subprocess.run(["ifconfig", self.ifname, "alias", addr,
                            "netmask", "255.255.255.0"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("  注意: %s への一時 IP %s の付与に失敗しました: %s"
                  % (self.ifname, addr, (r.stderr or "").strip()))
            return self
        self.addr = addr
        time.sleep(0.5)
        return self

    def __exit__(self, *exc):
        if self.addr:
            subprocess.run(["ifconfig", self.ifname, "-alias", self.addr],
                           capture_output=True)
            self.addr = None
        return False


# ---------------------------------------------------------------------------
# レンジ指定
# ---------------------------------------------------------------------------

RANGE_PRESETS = {
    # 工場出荷時のネットワーク。まずここ。
    "factory": ["192.168.249.0/24"],
    # 人間が手で設定しがちなレンジ
    "common": ["192.168.0.0/16", "172.16.0.0/12", "169.254.0.0/16"],
    # RFC1918 全域 + リンクローカル
    "all": ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8",
            "169.254.0.0/16"],
}


def parse_ranges(spec):
    nets = []
    for token in spec:
        token = token.strip()
        if token in RANGE_PRESETS:
            for c in RANGE_PRESETS[token]:
                nets.append(ipaddress.IPv4Network(c))
        else:
            nets.append(ipaddress.IPv4Network(token, strict=False))
    return collapse(nets)


def collapse(nets):
    """重複を潰して二度打ちを避ける。"""
    return list(ipaddress.collapse_addresses(nets))


# ---------------------------------------------------------------------------
# サブコマンド
# ---------------------------------------------------------------------------

def require_root():
    if os.geteuid() != 0:
        sys.exit("エラー: raw パケットの送受信に root 権限が必要です。"
                 "sudo で実行してください。")


def resolve_spa(spec):
    """--spa の指定を (mode, packed_ip) に落とす。"""
    if spec in ("peer", "probe"):
        return spec, None
    try:
        return "fixed", ipaddress.IPv4Address(spec).packed
    except ValueError:
        sys.exit("エラー: --spa には peer / probe / IPv4 アドレスを指定してください "
                 "(指定値: %s)" % spec)


def resolve_iface(args):
    if args.interface:
        i = get_interface(args.interface)
        if i is None:
            sys.exit("エラー: インターフェース %s が見つかりません。"
                     % args.interface)
        if i["mac"] is None:
            sys.exit("エラー: %s は MAC を持たない(イーサネットでない)"
                     "インターフェースです。" % args.interface)
        return i

    cands = [i for i in candidate_interfaces() if i["status"] == "active"]
    if len(cands) == 1:
        print("インターフェース %s を自動選択しました。" % cands[0]["name"])
        return cands[0]
    print("使用するインターフェースを -i で指定してください。候補:")
    for i in candidate_interfaces():
        print("  %-8s %s  status=%s  inet=%s"
              % (i["name"], i["mac"], i["status"],
                 ", ".join(a for a, _ in i["inet"]) or "なし"))
    sys.exit(1)


def looks_shared(iface):
    """共有ネットワークに繋がっている疑いがあるか。

    機器と 1 対 1 で直結したポートには DHCP サーバーが居ないので、通常
    IP は付かないか 169.254.x のセルフアサインになる。逆にまともな IP が
    付いていたり、デフォルトルートを持っていれば共有セグメントの疑いが濃い。
    """
    reasons = []
    if default_route_iface() == iface["name"]:
        reasons.append("デフォルトルートのインターフェース")
    for addr, _ in iface["inet"]:
        if not addr.startswith("169.254."):
            reasons.append("業務用らしき IP %s が付いている" % addr)
            break
    return reasons


def confirm_safety(args, iface, total, spa_mode):
    """共有ネットワークへの誤爆を止める。危険な組み合わせのみ確認を取る。"""
    reasons = looks_shared(iface)
    if not reasons:
        return True

    print("警告: %s は共有ネットワークに繋がっている疑いがあります。"
          % iface["name"])
    for r in reasons:
        print("      - %s" % r)
    print("      本ツールは機器と 1 対 1 で直結したポートでの使用を想定しています。")

    risky = spa_mode == "peer" or total > 4096
    if not risky:
        print("      (今回は送信量が少なく ARP 送信元も 0.0.0.0 なので続行します)")
        print()
        return True

    print()
    print("      この条件での実行は共有セグメントに影響します:")
    if spa_mode == "peer":
        print("      - --spa peer は ARP の送信元 IP を詐称します"
              "(他機器の ARP キャッシュを汚染します)")
    if total > 4096:
        print("      - %d アドレス分の ARP をこのセグメントに流します" % total)
    print()
    if getattr(args, "yes", False):
        print("      --yes が指定されているため続行します。")
        print()
        return True
    if not sys.stdin.isatty():
        print("エラー: 対話できない環境です。意図した実行なら --yes を付けてください。")
        return False
    try:
        ans = input("      本当に実行しますか? [y/N]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        return False
    print()
    return ans in ("y", "yes")


def cmd_ifaces(args):
    dflt = default_route_iface()
    for i in list_interfaces():
        if i["mac"] is None:
            continue
        mark = " <- デフォルトルート" if i["name"] == dflt else ""
        print("%-8s %s  status=%-8s inet=%s%s"
              % (i["name"], i["mac"], i["status"] or "-",
                 ", ".join(a for a, _ in i["inet"]) or "なし", mark))
    return 0


def passive_listen(iface, seconds, mac_filter=None, prefill=None,
                   wait_for_enter=True):
    """パッシブ待ち受け。ARP スイープの射程外に IP があっても効く唯一の手段。

    機器は起動時に Gratuitous ARP や DHCP DISCOVER を出すことが多く、その
    送信元アドレスから IP が判明する。こちらから宛先 IP を当てる必要が無いので、
    RFC1918 外に設定されていても見つかる。
    """
    print("この間に %s に繋いだ機器の電源を入れ直してください。" % iface["name"])
    print("起動時のパケットで IP が判明することがあります。")
    print("(ARP スイープと違い、どの IP 帯に設定されていても効きます)")
    if wait_for_enter and sys.stdin.isatty():
        try:
            input("電源を入れる準備ができたら Enter (スキップは Ctrl-C): ")
        except (KeyboardInterrupt, EOFError):
            print("\n  待ち受けをスキップします。")
            return {}
    print()

    bpf = Bpf(iface["name"], promisc=True)
    sw = ArpSweeper(bpf, mac_to_bytes(iface["mac"]), mac_filter=mac_filter)
    if prefill:
        sw.found.update(prefill)
    try:
        sw.start_reader()
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            sys.stderr.write("\r\033[K  待ち受け中... 残り %d 秒  発見 %d 件"
                             % (deadline - time.monotonic(), len(sw.found)))
            sys.stderr.flush()
            time.sleep(0.3)
    except KeyboardInterrupt:
        pass
    finally:
        sys.stderr.write("\r\033[K")
        sw.stop_reader(settle=0)
        bpf.close()
    return sw.found


def cmd_sniff(args):
    require_root()
    iface = resolve_iface(args)
    if not confirm_safety(args, iface, total=0, spa_mode="probe"):
        return 1
    print("=== パッシブ待ち受け (%d 秒) ===" % args.seconds)
    found = passive_listen(iface, args.seconds, mac_filter=args.mac)
    return report(found, iface, args)


def sweep_once(iface, nets, args, spa_mode, fixed, prefill=None):
    """1 レンジ分の ARP スイープ。fd は必ず閉じる。"""
    bpf = Bpf(iface["name"], promisc=True, bpf_filter=BPF_FILTER_ARP_IP)
    sw = ArpSweeper(bpf, mac_to_bytes(iface["mac"]), spa_mode=spa_mode,
                    fixed_spa=fixed, pps=args.pps, retries=args.retries,
                    mac_filter=args.mac)
    if prefill:
        sw.found.update(prefill)
    try:
        sw.start_reader()
        sw.sweep(nets)
    finally:
        sw.stop_reader(settle=args.settle)
        bpf.close()
    return sw.found


def cmd_scan(args):
    require_root()
    iface = resolve_iface(args)
    nets = parse_ranges(args.ranges)
    total = sum(n.num_addresses for n in nets)
    spa_mode, fixed = resolve_spa(args.spa)
    if not confirm_safety(args, iface, total * args.retries, spa_mode):
        return 1

    print("=== ARP スイープ ===")
    print("インターフェース : %s (%s)" % (iface["name"], iface["mac"]))
    print("対象レンジ       : %s" % ", ".join(str(n) for n in nets))
    print("アドレス数       : %d  x %d 回  (%d pps, 概算 %s)"
          % (total, args.retries, args.pps,
             fmt_duration(total * args.retries / args.pps)))
    print("送信元 IP        : %s" % args.spa)
    print()

    found = sweep_once(iface, nets, args, spa_mode, fixed)
    return report(found, iface, args)


def cmd_selftest(args):
    """機器を繋ぐ前に、ツール自体が動くことを既知のネットワークで確かめる。"""
    print("=== 1. ロジック検証 (root 不要) ===")
    src = mac_to_bytes("00:11:22:33:44:55")
    f = build_arp_request(src, spa_for(0x0A010203, "peer", None),
                          struct.pack("!I", 0x0A010203))
    checks = [
        ("ARP フレーム 42 バイト", len(f) == 42),
        ("ethertype = 0x0806", f[12:14] == b"\x08\x06"),
        ("op = request", struct.unpack_from("!H", f, 20)[0] == 1),
        ("送信元 MAC", f[6:12] == src and f[22:28] == src),
        ("spa=peer は同一/24", f[28:32] == b"\x0a\x01\x02\x01"),
        ("tpa", f[38:42] == b"\x0a\x01\x02\x03"),
        ("spa=probe は 0.0.0.0", spa_for(1, "probe", None) == b"\x00" * 4),
        ("struct timeval = 16B", struct.calcsize("@qi4x") == 16),
        ("struct bpf_program = 16B", struct.calcsize("@IQ") == 16),
        ("struct bpf_insn = 8B", struct.calcsize("@HBBI") == 8),
    ]
    pkt = bytes(range(60))
    rec = struct.pack("@iiIIH", 1, 2, 60, 60, 20) + b"\x00" * 2 + pkt
    checks.append(("BPF レコード解析", list(Bpf._parse(rec * 2)) == [pkt, pkt]))
    ng = 0
    for name, cond in checks:
        print("  %s %s" % ("OK  " if cond else "NG  ", name))
        ng += 0 if cond else 1
    if ng:
        print("\nロジック検証に失敗しました。")
        return 1

    print()
    print("=== 2. 実機検証 (BPF 送受信) ===")
    require_root()
    iface = resolve_iface(args)
    if not iface["inet"]:
        print("  %s に IP が付いていないため、既知ホストでの検証はできません。"
              % iface["name"])
        print("  IP の付いたインターフェースを -i で指定してください。")
        return 1
    addr, mask = iface["inet"][0]
    net = ipaddress.IPv4Network("%s/%s" % (addr, ipaddress.IPv4Address(mask)),
                                strict=False)
    if net.num_addresses > 4096:
        net = ipaddress.IPv4Network("%s/24" % addr, strict=False)
    print("  %s の %s を ARP スイープします (送信元 0.0.0.0 / ARP probe)"
          % (iface["name"], net))
    print("  自分以外に 1 台でも応答すれば BPF の送受信は正常です。")
    print()
    bpf = Bpf(iface["name"], promisc=True, bpf_filter=BPF_FILTER_ARP_IP)
    sw = ArpSweeper(bpf, mac_to_bytes(iface["mac"]), spa_mode="probe",
                    pps=1000, retries=2)
    try:
        sw.start_reader()
        sw.sweep([net])
    finally:
        sw.stop_reader(settle=2.0)
        bpf.close()
    others = [ip for ip in sw.found if ip != addr]
    print()
    if others:
        print("SELFTEST: PASS  (%d 台が応答しました)" % len(sw.found))
        return 0
    print("SELFTEST: FAIL  (応答が 0 件)")
    print("  リンクが上がっているか、-i の指定が正しいか確認してください。")
    return 1


def cmd_verify(args):
    iface = get_interface(args.interface) if args.interface else None
    found = {ip: {"mac": "-", "how": "manual"} for ip in args.hosts}
    return report(found, iface, args)


def cmd_auto(args):
    require_root()
    iface = resolve_iface(args)
    spa_mode, fixed = resolve_spa(args.spa)
    worst = max((sum(n.num_addresses for n in parse_ranges([s]))
                 for s in args.stages), default=0)
    if not confirm_safety(args, iface, worst * args.retries, spa_mode):
        return 1

    all_found = {}
    if args.sniff_seconds > 0:
        print("=== ステップ 1/2: パッシブ待ち受け (%d 秒) ==="
              % args.sniff_seconds)
        all_found.update(passive_listen(iface, args.sniff_seconds,
                                        mac_filter=args.mac,
                                        wait_for_enter=not args.yes))
        print()

    print("=== ステップ 2/2: ARP スイープ ===")
    swept = []
    for preset in args.stages:
        # 前段で掃いたレンジは二度打ちしない
        nets = [n for n in parse_ranges([preset])
                if not any(n.subnet_of(p) for p in swept)]
        if not nets:
            continue
        swept.extend(nets)
        total = sum(n.num_addresses for n in nets)
        print("-- %s (%s / %d アドレス / 概算 %s)"
              % (preset, ", ".join(str(n) for n in nets), total,
                 fmt_duration(total * args.retries / args.pps)))
        found = sweep_once(iface, nets, args, spa_mode, fixed,
                           prefill=all_found)
        new = len(found) - len(all_found)
        all_found.update(found)
        if new > 0 and args.stop_on_hit:
            print("  この段で %d 件の応答があったので以降のスイープを省略します。"
                  % new)
            break
        print()

    return report(all_found, iface, args)


def report(found, iface, args):
    print()
    print("=" * 66)
    if not found:
        print("応答したホストはありませんでした。")
        print()
        print("確認してください:")
        print("  1. ツール自体が動いているか")
        print("     sudo python3 ipsearch.py selftest -i <IPの付いたIF>")
        print("     ここが FAIL ならツール側の問題です。")
        print("  2. Mac と機器が Ethernet ケーブルで直結されているか")
        print("     (機器の LAN ランプが緑点灯なら L2 リンクは上がっています。"
              "オレンジ点灯はリンクなし)")
        print("  3. -i で正しいインターフェースを指定しているか (ifaces で確認)")
        print("  4. --spa peer に切り替えて再試行")
        print("     (サブネット外からの ARP に応答しない実装への対策)")
        print("  5. --pps 5000 --retries 3 で取りこぼしを減らす")
        print("  6. --ranges all で RFC1918 全域を掃く")
        print()
        print("  ARP スイープは宛先 IP を総当たりする方式なので、IPv4 全空間は"
              "掃けません。")
        print("  RFC1918 外(グローバルアドレス帯など)に設定されていると原理的に"
              "当たりません。")
        print("  その場合に効くのは IP 帯に依存しないパッシブ待ち受けだけです:")
        print("     sudo python3 ipsearch.py sniff -i <IF> --seconds 180")
        print("     ↑ 待ち受け中に機器の電源を入れ直してください。")
        return 1

    print("応答したホスト: %d 件" % len(found))
    print()

    results = []
    ifname = iface["name"] if iface else None
    for ip in sorted(found, key=lambda s: ipaddress.IPv4Address(s)):
        entry = dict(found[ip])
        entry["ip"] = ip
        if not args.no_http:
            alias = TempAlias(ifname, ip,
                              enabled=bool(ifname) and not args.no_alias)
            if alias.needs_root() and os.geteuid() != 0:
                print("  注意: %s に到達するには同一サブネットの IP が必要ですが、"
                      "root 権限が無いため付与できません (sudo で実行してください)"
                      % ip)
            with alias:
                info = identify(ip, port=args.port, timeout=args.http_timeout,
                                try_creds="all" if args.try_creds else "model")
            if info:
                entry.update({k: v for k, v in info.items() if k != "ip"})
        results.append(entry)

    hits = [r for r in results if r.get("model")]
    for r in results:
        tag = "★ 対象機器" if r.get("model") else "  "
        print("%s %-15s  mac=%s  (%s)" % (tag, r["ip"], r["mac"], r["how"]))
        if r.get("model"):
            print("      機種   : %s" % r["model"])
        if r.get("realm"):
            print("      realm  : %s" % r["realm"])
        if r.get("http_status"):
            print("      HTTP   : %s%s" % (r["http_status"],
                                           "  (認証成功: %s)" % r["creds"]
                                           if r.get("creds") else ""))
        for k, v in (r.get("detail") or {}).items():
            print("      %-7s: %s" % (k, v))

    print()
    if hits:
        h = hits[0]
        print("=" * 66)
        print("対象機器を特定しました: %s" % h["ip"])
        print()
        print("設定画面を開く手順:")
        url = ("http://%s/" % h["ip"] if args.port == 80
               else "http://%s:%d/" % (h["ip"], args.port))
        step = 1
        if not TempAlias(ifname, h["ip"])._already_reachable():
            net = ipaddress.IPv4Network("%s/24" % h["ip"], strict=False)
            pc = ipaddress.IPv4Address(int(net.network_address) | 0xFE)
            if str(pc) == h["ip"]:
                pc = ipaddress.IPv4Address(int(net.network_address) | 0xFD)
            print("  %d. Mac の %s に %s/24 を追加して同一サブネットに入る"
                  % (step, ifname or "直結ポート", pc))
            print("     sudo ifconfig %s alias %s netmask 255.255.255.0"
                  % (ifname or "<インターフェース>", pc))
            print("     (作業後に外す: sudo ifconfig %s -alias %s)"
                  % (ifname or "<インターフェース>", pc))
            step += 1
        print("  %d. ブラウザで %s を開く" % (step, url))
        step += 1
        print("  %d. ユーザー名 %s / パスワード 999999"
              % (step, h.get("model") or "WJ-PR204"))
        step += 1
        print("  %d. Option 画面で IP アドレスを控える"
              "(または使いたい値に変更してメモする)" % step)
        print()
        print("  ※ 設定画面が開かない場合は sudo arp -d -a で ARP テーブルを"
              "消してから再試行してください。")
    else:
        print("i-PRO 同軸-LANコンバーターとして同定できたホストはありません。")
        print("上記の応答ホストを 1 つずつブラウザで開いて確認してください。")

    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print()
        print("結果を %s に書き出しました。" % args.out)

    return 0 if hits else 2


# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="ipsearch",
        description="i-PRO 同軸-LANコンバーター(WJ-PR204UX 等)の IP を探す",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
使用例:
  sudo ./ipsearch.py ifaces
  sudo ./ipsearch.py auto -i en5
  sudo ./ipsearch.py scan -i en5 --ranges common
  sudo ./ipsearch.py scan -i en5 --ranges 10.0.0.0/8 --pps 30000
  sudo ./ipsearch.py sniff -i en5 --seconds 30
""")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, need_iface=True):
        if need_iface:
            sp.add_argument("-i", "--interface",
                            help="機器と直結しているインターフェース (例 en5)")
        sp.add_argument("--mac",
                        help="機器の MAC が分かっている場合の絞り込み")
        sp.add_argument("--port", type=int, default=80,
                        help="HTTP 判定に使うポート (既定 80)")
        sp.add_argument("--http-timeout", type=float, default=3.0)
        sp.add_argument("--no-http", action="store_true",
                        help="HTTP による機種判定を行わない")
        sp.add_argument("--no-alias", action="store_true",
                        help="HTTP 判定時に一時 IP エイリアスを追加しない")
        sp.add_argument("--try-creds", action="store_true",
                        help="機種を同定できなかった 401 ホストにも既定パスワードを試す"
                             "(共有NWでは使わないこと)")
        sp.add_argument("-y", "--yes", action="store_true",
                        help="共有ネットワークの警告に対する確認を省略する")
        sp.add_argument("--out", help="結果を JSON で書き出すパス")

    sp = sub.add_parser("ifaces", help="インターフェース一覧を表示")
    sp.set_defaults(func=cmd_ifaces)

    sp = sub.add_parser("sniff", help="パッシブ待ち受け(機器の電源投入で検出)")
    common(sp)
    sp.add_argument("--seconds", type=int, default=60)
    sp.set_defaults(func=cmd_sniff)

    sp = sub.add_parser("scan", help="ARP スイープ")
    common(sp)
    sp.add_argument("--ranges", nargs="+", default=["factory", "common"],
                    help="factory / common / all またはCIDR (既定: factory common)")
    sp.add_argument("--pps", type=int, default=20000, help="送信レート")
    sp.add_argument("--retries", type=int, default=2, help="スイープ回数")
    sp.add_argument("--spa", default="probe",
                    help="ARP 送信元 IP: probe(0.0.0.0/既定) / peer(同一/24を名乗る) / 固定IP")
    sp.add_argument("--settle", type=float, default=3.0,
                    help="送信完了後に応答を待つ秒数")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("auto", help="待ち受け -> 段階的スイープ -> 同定")
    common(sp)
    sp.add_argument("--sniff-seconds", type=int, default=60)
    sp.add_argument("--stages", nargs="+",
                    default=["factory", "common", "all"],
                    help="スイープする段階 (既定: factory common all)")
    sp.add_argument("--pps", type=int, default=20000)
    sp.add_argument("--retries", type=int, default=2)
    sp.add_argument("--spa", default="probe")
    sp.add_argument("--settle", type=float, default=3.0)
    sp.add_argument("--stop-on-hit", action="store_true", default=True)
    sp.add_argument("--no-stop-on-hit", dest="stop_on_hit",
                    action="store_false")
    sp.set_defaults(func=cmd_auto)

    sp = sub.add_parser("selftest", help="ツール自体が動くかを既知NWで確認")
    common(sp)
    sp.set_defaults(func=cmd_selftest)

    sp = sub.add_parser("verify", help="指定した IP を HTTP で判定するだけ")
    common(sp)
    sp.add_argument("hosts", nargs="+")
    sp.set_defaults(func=cmd_verify)

    return p


def main():
    if sys.platform != "darwin":
        sys.exit("エラー: 本ツールは macOS 専用です (BPF を直接使用します)。")
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except PermissionError as e:
        sys.exit("エラー: %s" % e)
    except KeyboardInterrupt:
        sys.stderr.write("\n中断しました。\n")
        return 130


if __name__ == "__main__":
    sys.exit(main())
