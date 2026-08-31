#!/usr/bin/env python3
from __future__ import annotations

import socket
import struct
import threading
import time
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import socks_auth_relay


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        piece = conn.recv(size - len(buf))
        if not piece:
            raise ConnectionError("closed")
        buf.extend(piece)
    return bytes(buf)


def _start_auth_socks_and_http():
    http = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    http.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    http.bind(("127.0.0.1", 0))
    http.listen(8)
    http_port = http.getsockname()[1]

    def http_serve():
        try:
            conn, _ = http.accept()
            conn.recv(4096)
            body = b"relay-ok"
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                % len(body)
                + body
            )
            conn.close()
        finally:
            http.close()

    threading.Thread(target=http_serve, daemon=True).start()

    upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    upstream.bind(("127.0.0.1", 0))
    upstream.listen(8)
    up_port = upstream.getsockname()[1]
    seen = {"user": "", "host": "", "port": 0}

    def socks_serve():
        try:
            conn, _ = upstream.accept()
            _ver, nmethods = _recv_exact(conn, 2)
            if nmethods:
                _recv_exact(conn, nmethods)
            conn.sendall(b"\x05\x02")
            auth_ver, ulen = _recv_exact(conn, 2)
            user = _recv_exact(conn, ulen).decode()
            plen = _recv_exact(conn, 1)[0]
            password = _recv_exact(conn, plen).decode()
            seen["user"] = user
            seen["password"] = password
            conn.sendall(b"\x01\x00")
            req = _recv_exact(conn, 4)
            atyp = req[3]
            if atyp == 3:
                n = _recv_exact(conn, 1)[0]
                host = _recv_exact(conn, n).decode()
            elif atyp == 1:
                host = socket.inet_ntoa(_recv_exact(conn, 4))
            else:
                host = "?"
            port = struct.unpack("!H", _recv_exact(conn, 2))[0]
            seen["host"] = host
            seen["port"] = port
            remote = socket.create_connection((host, port), timeout=5)
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

            def pump(src, dst):
                try:
                    while True:
                        data = src.recv(65536)
                        if not data:
                            break
                        dst.sendall(data)
                except Exception:
                    pass

            t1 = threading.Thread(target=pump, args=(conn, remote), daemon=True)
            t2 = threading.Thread(target=pump, args=(remote, conn), daemon=True)
            t1.start()
            t2.start()
            t1.join(timeout=5)
            t2.join(timeout=5)
            conn.close()
            remote.close()
        finally:
            upstream.close()

    threading.Thread(target=socks_serve, daemon=True).start()
    time.sleep(0.05)
    return up_port, http_port, seen


def test_wrap_firefox_proxy_starts_local_relay():
    up_port, http_port, seen = _start_auth_socks_and_http()
    proxy, relay = socks_auth_relay.wrap_firefox_proxy(
        {
            "server": f"socks5h://127.0.0.1:{up_port}",
            "username": "g2a.demo",
            "password": "secret",
        }
    )
    try:
        assert relay is not None
        assert proxy["server"].startswith("socks5://127.0.0.1:")
        assert "username" not in proxy
        client = socket.create_connection(("127.0.0.1", relay.port), timeout=5)
        client.sendall(b"\x05\x01\x00")
        assert client.recv(2) == b"\x05\x00"
        host = b"127.0.0.1"
        req = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", http_port)
        client.sendall(req)
        reply = _recv_exact(client, 10)
        assert reply[1] == 0x00
        client.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        body = b""
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            body += chunk
        client.close()
        assert b"relay-ok" in body
        assert seen["user"] == "g2a.demo"
        assert seen["password"] == "secret"
        assert seen["port"] == http_port
    finally:
        if relay is not None:
            relay.stop()


def test_wrap_http_proxy_unchanged():
    proxy, relay = socks_auth_relay.wrap_firefox_proxy(
        {
            "server": "http://127.0.0.1:7890",
            "username": "u",
            "password": "p",
        }
    )
    assert relay is None
    assert proxy["server"] == "http://127.0.0.1:7890"
    assert proxy["username"] == "u"


if __name__ == "__main__":
    test_wrap_firefox_proxy_starts_local_relay()
    test_wrap_http_proxy_unchanged()
    print("ok")
