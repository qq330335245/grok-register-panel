# -*- coding: utf-8 -*-
"""Local SOCKS5 (no auth) → upstream SOCKS5 (username/password).

Playwright/Camoufox Firefox rejects SOCKS5 proxy authentication:
`Browser does not support socks5 proxy authentication`.
Passing socks5h://user:pass@host still launches, but Firefox does not
authenticate, so accounts.x.ai dies with NS_ERROR_NET_RESET.
"""
from __future__ import annotations

import socket
import struct
import threading
from typing import Optional
from urllib.parse import urlparse

import socks


class SocksAuthRelay:
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        *,
        bind_host: str = "127.0.0.1",
    ) -> None:
        self.upstream_host = host
        self.upstream_port = int(port)
        self.username = username
        self.password = password
        self.bind_host = bind_host
        self.port = 0
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def local_server(self) -> str:
        return f"socks5://{self.bind_host}:{self.port}"

    def start(self) -> str:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.bind_host, 0))
        srv.listen(128)
        srv.settimeout(0.5)
        self._sock = srv
        self.port = int(srv.getsockname()[1])
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._serve,
            name=f"socks-auth-relay-{self.port}",
            daemon=True,
        )
        self._thread.start()
        return self.local_server

    def stop(self) -> None:
        self._stop.set()
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        thread = self._thread
        self._thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    def _serve(self) -> None:
        while not self._stop.is_set():
            sock = self._sock
            if sock is None:
                break
            try:
                conn, _addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            worker = threading.Thread(
                target=self._handle,
                args=(conn,),
                name="socks-auth-relay-conn",
                daemon=True,
            )
            worker.start()

    def _handle(self, conn: socket.socket) -> None:
        remote = None
        try:
            conn.settimeout(30)
            header = _recv_exact(conn, 2)
            if header[0] != 0x05:
                return
            nmethods = header[1]
            if nmethods:
                _recv_exact(conn, nmethods)
            conn.sendall(b"\x05\x00")
            req = _recv_exact(conn, 4)
            if req[0] != 0x05 or req[1] != 0x01:
                conn.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            atyp = req[3]
            if atyp == 0x01:
                addr = socket.inet_ntoa(_recv_exact(conn, 4))
            elif atyp == 0x03:
                length = _recv_exact(conn, 1)[0]
                addr = _recv_exact(conn, length).decode("idna", "surrogateescape")
            elif atyp == 0x04:
                addr = socket.inet_ntop(socket.AF_INET6, _recv_exact(conn, 16))
            else:
                conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            port = struct.unpack("!H", _recv_exact(conn, 2))[0]
            remote = socks.socksocket()
            remote.set_proxy(
                socks.SOCKS5,
                self.upstream_host,
                self.upstream_port,
                rdns=True,
                username=self.username,
                password=self.password,
            )
            remote.settimeout(30)
            remote.connect((addr, port))
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            _pipe(conn, remote)
        except Exception:
            try:
                conn.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            except Exception:
                pass
        finally:
            for item in (remote, conn):
                if item is None:
                    continue
                try:
                    item.close()
                except Exception:
                    pass


def wrap_firefox_proxy(proxy: dict | None) -> tuple[dict, Optional[SocksAuthRelay]]:
    """Return a Playwright Firefox-safe proxy dict and optional local relay."""
    if not proxy:
        return {}, None
    server = str(proxy.get("server") or "").strip()
    if not server:
        return dict(proxy), None
    parsed = urlparse(server if "://" in server else f"socks5://{server}")
    scheme = (parsed.scheme or "").lower()
    username = str(proxy.get("username") or parsed.username or "")
    password = str(proxy.get("password") or parsed.password or "")
    if scheme not in {"socks5", "socks5h"}:
        return dict(proxy), None
    host = parsed.hostname
    port = parsed.port or 1080
    if not host:
        return dict(proxy), None
    if not username:
        return {"server": f"socks5://{host}:{port}"}, None
    relay = SocksAuthRelay(host, port, username, password)
    local = relay.start()
    return {"server": local}, relay


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        piece = conn.recv(size - len(chunks))
        if not piece:
            raise ConnectionError("SOCKS client closed")
        chunks.extend(piece)
    return bytes(chunks)


def _pipe(left: socket.socket, right: socket.socket) -> None:
    def pump(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass

    first = threading.Thread(target=pump, args=(left, right), daemon=True)
    second = threading.Thread(target=pump, args=(right, left), daemon=True)
    first.start()
    second.start()
    first.join()
    second.join()
