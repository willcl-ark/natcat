#!/usr/bin/env python3
# Copyright (c)
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Naive TCP hole-punch prototype with UDP coordination.

This a small tool for checking whether two hosts can coordinate over UDP and
then exchange data over a direct TCP connection. Once the TCP connection is
established, lines typed on stdin are sent to the peer and displayed on the
other side.

Manual endpoint exchange:

    client.py peer --name alice
    client.py peer --name bob
    # Copy the printed STUN endpoints, then run both peers with --peer:
    client.py peer --name alice --peer BOB_PUBLIC_IP:PORT
    client.py peer --name bob --peer ALICE_PUBLIC_IP:PORT

Run both peers with each other's printed public endpoint to test UDP
coordination and direct TCP reachability.

Default rendezvous lobby:

    rendezvous.py --bind 0.0.0.0:3479
    client.py peer --name alice --auto-connect
    client.py peer --name bob

Peers join the hardcoded "btcpunch" lobby. The rendezvous server assigns
base58 endpoint ids from observed UDP source addresses and advertised TCP
ports. Type /connect ENDPOINT_ID to invite a peer from the lobby.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import ipaddress
import json
import os
import secrets
import select
import socket
import struct
import sys
import time
from typing import Any, Optional, TextIO


DEFAULT_BIND = "0.0.0.0:50000"
DEFAULT_RENDEZVOUS = "stun.fish.foo:3479"
LOBBY = "btcpunch"
DEFAULT_STUN = "stun.fish.foo:3478"
CONNECT_TIMEOUT = 1.0

JSON_MAGIC = "btcpunch-udp-v1"
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_SUCCESS = 0x0101
STUN_MAGIC_COOKIE = 0x2112A442
STUN_XOR_MAPPED_ADDRESS = 0x0020
STUN_MAPPED_ADDRESS = 0x0001


Address = tuple[Any, ...]


def log(message: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} {message}", flush=True)


def log_event(kind: str, message: str) -> None:
    log(f"[{kind}] {message}")


def log_peer_commands() -> None:
    log_event("commands", "/connect ENDPOINT_ID, /list, /help")


def parse_host_port(value: str) -> tuple[str, int]:
    if value.startswith("["):
        end = value.find("]")
        if end == -1 or len(value) <= end + 2 or value[end + 1] != ":":
            raise argparse.ArgumentTypeError(f"invalid endpoint: {value}")
        host = value[1:end]
        port_text = value[end + 2 :]
    else:
        if ":" not in value:
            raise argparse.ArgumentTypeError(f"missing port in endpoint: {value}")
        host, port_text = value.rsplit(":", 1)

    try:
        port = int(port_text)
    except ValueError as err:
        raise argparse.ArgumentTypeError(f"invalid port in endpoint: {value}") from err

    if port < 0 or port > 65535:
        raise argparse.ArgumentTypeError(f"port out of range in endpoint: {value}")

    return host, port


def resolve_endpoint(
    value: str,
    family: int = socket.AF_UNSPEC,
    socktype: int = socket.SOCK_DGRAM,
) -> Address:
    host, port = parse_host_port(value)
    infos = socket.getaddrinfo(host, port, family, socktype)
    if not infos:
        raise OSError(f"could not resolve {value}")
    return infos[0][4]


def short_addr(addr: Address) -> str:
    host, port = addr[0], addr[1]
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def socket_addr(sock: socket.socket) -> str:
    try:
        return short_addr(sock.getsockname())
    except OSError as err:
        return f"<closed: {err}>"


def make_udp_socket(bind_value: str) -> socket.socket:
    bind_addr = resolve_endpoint(bind_value)
    family = socket.AF_INET6 if len(bind_addr) == 4 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    sock.bind(bind_addr)
    return sock


def encode_json(message: dict[str, Any]) -> bytes:
    message = {"magic": JSON_MAGIC, **message}
    return json.dumps(message, separators=(",", ":"), sort_keys=True).encode()


def decode_json(data: bytes) -> Optional[dict[str, Any]]:
    try:
        message = json.loads(data.decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(message, dict) or message.get("magic") != JSON_MAGIC:
        return None
    return message


def send_json(sock: socket.socket, addr: Address, message: dict[str, Any]) -> None:
    sock.sendto(encode_json(message), addr)


def decode_stun_address(
    value: bytes, transaction_id: bytes, xor: bool
) -> tuple[str, int]:
    if len(value) < 4 or value[0] != 0:
        raise ValueError("invalid STUN address attribute")

    family = value[1]
    port = struct.unpack("!H", value[2:4])[0]
    addr = value[4:]

    if family == 0x01:
        if len(addr) != 4:
            raise ValueError("invalid IPv4 STUN address")
        if xor:
            port ^= STUN_MAGIC_COOKIE >> 16
            key = struct.pack("!I", STUN_MAGIC_COOKIE)
            addr = bytes(byte ^ key[i] for i, byte in enumerate(addr))
        return str(ipaddress.ip_address(addr)), port

    if family == 0x02:
        if len(addr) != 16:
            raise ValueError("invalid IPv6 STUN address")
        if xor:
            port ^= STUN_MAGIC_COOKIE >> 16
            key = struct.pack("!I", STUN_MAGIC_COOKIE) + transaction_id
            addr = bytes(byte ^ key[i] for i, byte in enumerate(addr))
        return str(ipaddress.ip_address(addr)), port

    raise ValueError("unknown STUN address family")


def parse_stun_response(
    data: bytes, transaction_id: bytes
) -> Optional[tuple[str, int]]:
    if len(data) < 20:
        return None

    message_type, message_len, cookie = struct.unpack("!HHI", data[:8])
    if message_type != STUN_BINDING_SUCCESS:
        return None
    if message_len + 20 > len(data):
        return None
    if cookie != STUN_MAGIC_COOKIE or data[8:20] != transaction_id:
        return None

    mapped = None
    offset = 20
    end = 20 + message_len
    while offset + 4 <= end:
        attr_type, attr_len = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        value = data[offset : offset + attr_len]
        offset += (attr_len + 3) & ~3

        if attr_type == STUN_XOR_MAPPED_ADDRESS:
            return decode_stun_address(value, transaction_id, xor=True)
        if attr_type == STUN_MAPPED_ADDRESS:
            mapped = decode_stun_address(value, transaction_id, xor=False)

    return mapped


def stun_binding(
    sock: socket.socket, server: Address, timeout: float
) -> tuple[str, int]:
    transaction_id = secrets.token_bytes(12)
    request = struct.pack(
        "!HHI12s", STUN_BINDING_REQUEST, 0, STUN_MAGIC_COOKIE, transaction_id
    )
    old_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        sock.sendto(request, server)
        while True:
            data, _addr = sock.recvfrom(2048)
            response = parse_stun_response(data, transaction_id)
            if response is not None:
                return response
    finally:
        sock.settimeout(old_timeout)


def default_name() -> str:
    return f"{socket.gethostname()}-{os.getpid()}"


def run_stun(args: argparse.Namespace) -> int:
    sock = make_udp_socket(args.bind)
    log_event("UDP STUN", f"bound {short_addr(sock.getsockname())}")
    for server_text in args.stun:
        server = resolve_endpoint(server_text, sock.family)
        try:
            mapped = stun_binding(sock, server, args.timeout)
        except socket.timeout:
            log_event("UDP STUN", f"{server_text} timed out")
            continue
        except OSError as err:
            log_event("UDP STUN", f"{server_text} failed: {err}")
            continue
        log_event("UDP STUN", f"{server_text} mapped us as {mapped[0]}:{mapped[1]}")
    return 0


# Optional public-endpoint discovery used by this Python CLI.
def run_peer_stun_probes(
    sock: socket.socket, server_texts: list[str], timeout: float, tcp_port: int
) -> None:
    for server_text in server_texts:
        server = resolve_endpoint(server_text, sock.family)
        try:
            mapped = stun_binding(sock, server, timeout)
        except socket.timeout:
            log_event("UDP STUN", f"{server_text} timed out")
            continue
        except OSError as err:
            log_event("UDP STUN", f"{server_text} failed: {err}")
            continue
        log_event("UDP STUN", f"{server_text} mapped us as {mapped[0]}:{mapped[1]}")
        log_event("TCP manual", f"share with peer: --peer {mapped[0]}:{tcp_port}")


@dataclass
class PeerConfig:
    name: str
    session: str


def close_socket(sock: Optional[socket.socket]) -> None:
    if sock is not None:
        sock.close()


def make_tcp_listener(bind_addr: Address) -> socket.socket:
    family = socket.AF_INET6 if len(bind_addr) == 4 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    sock.bind(bind_addr)
    sock.listen(1)
    sock.setblocking(False)
    return sock


def make_tcp_connector(bind_addr: Address, peer: Address) -> socket.socket:
    family = socket.AF_INET6 if len(bind_addr) == 4 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    sock.bind(bind_addr)
    sock.setblocking(False)
    sock.connect_ex(peer)
    return sock


def tcp_verify_command(sock: socket.socket) -> str:
    local_port = sock.getsockname()[1]
    return f"ss -tnp state established '( sport = :{local_port} or dport = :{local_port} )'"


# Core TCP hole-punch state: listener, connector, and established socket only.
@dataclass
class TcpCandidate:
    sock: socket.socket
    peer: Address
    inbound: bool


class TcpPuncher:
    def __init__(
        self,
        bind_addr: Address,
        interval: float,
        start_at: float,
        connect_timeout: float = CONNECT_TIMEOUT,
    ) -> None:
        self.bind_addr = bind_addr
        self.interval = interval
        self.start_at = start_at
        self.connect_timeout = connect_timeout

        self.listener: Optional[socket.socket] = make_tcp_listener(bind_addr)
        self.connector: Optional[socket.socket] = None
        self.connector_expires_at = 0.0
        self.connector_peer: Optional[Address] = None
        self.connector_started_at = 0.0
        self.established: Optional[socket.socket] = None

        self.peer: Optional[Address] = None
        self.next_connect = 0.0
        self.connect_attempt = 0

    @property
    def connected(self) -> bool:
        return self.established is not None

    @property
    def tcp_port(self) -> int:
        return int(self.bind_addr[1])

    def listener_status(self) -> str:
        if self.listener is None:
            return "closed"
        return f"open on {socket_addr(self.listener)}"

    def read_sockets(self) -> list[socket.socket]:
        sockets: list[socket.socket] = []
        if self.listener is not None:
            sockets.append(self.listener)
        if self.established is not None:
            sockets.append(self.established)
        return sockets

    def write_sockets(self) -> list[socket.socket]:
        return [self.connector] if self.connector is not None else []

    def set_peer(
        self,
        peer: Address,
        start_at: float,
        close_connector_reason: Optional[str] = None,
    ) -> None:
        if close_connector_reason is not None:
            self.close_connector(close_connector_reason)
        self.peer = peer
        self.start_at = start_at

    def close_connector(self, reason: str) -> None:
        if self.connector is not None:
            age = time.monotonic() - self.connector_started_at
            peer_text = (
                short_addr(self.connector_peer)
                if self.connector_peer
                else "<unknown>"
            )
            log_event(
                "TCP holepunch",
                f"{reason}: closing connector {socket_addr(self.connector)} -> "
                f"{peer_text} after {age:.3f}s; listener={self.listener_status()}",
            )
        close_socket(self.connector)
        self.connector = None
        self.connector_expires_at = 0.0
        self.connector_peer = None
        self.connector_started_at = 0.0

    def reset_connection(self, reason: str) -> None:
        log_event("TCP holepunch", reason)
        close_socket(self.established)
        self.established = None
        self.close_connector("reset")
        if self.listener is None:
            self._reopen_listener()

    def tick(self, now: float) -> None:
        if self.established is not None:
            return

        if self.connector is not None and now >= self.connector_expires_at:
            self.close_connector(f"connect timed out after {self.connect_timeout:.3f}s")
            self.next_connect = now

        if (
            self.connector is None
            and self.peer is not None
            and now >= self.start_at
            and now >= self.next_connect
        ):
            self._start_connect(now)

    def connector_ready(self, now: float) -> Optional[TcpCandidate]:
        if self.connector is None:
            return None

        active_peer = self.connector_peer or self.peer
        if active_peer is None:
            self.close_connector("connect cancelled: no active peer")
            return None

        err = self.connector.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err == 0:
            candidate_sock = self.connector
            self.connector = None
            self.connector_expires_at = 0.0
            self.connector_peer = None
            self.connector_started_at = 0.0
            return TcpCandidate(candidate_sock, active_peer, inbound=False)

        log_event(
            "TCP holepunch",
            f"connect to {short_addr(active_peer)} failed: {os.strerror(err)}",
        )
        self.close_connector("connect failed")
        self.next_connect = now + max(self.interval, 1.0)
        return None

    def accept_ready(self) -> Optional[TcpCandidate]:
        if self.listener is None:
            return None
        try:
            accepted_sock, accepted_addr = self.listener.accept()
        except BlockingIOError:
            return None
        accepted_sock.setblocking(False)
        return TcpCandidate(accepted_sock, accepted_addr, inbound=True)

    def adopt_connection(self, candidate: TcpCandidate) -> None:
        self.established = candidate.sock
        if candidate.inbound:
            self.close_connector("accepted inbound connection")

        if self.listener is not None:
            direction = "inbound accept" if candidate.inbound else "outbound connect"
            log_event(
                "TCP listen",
                f"closing {socket_addr(self.listener)} after {direction}",
            )
        close_socket(self.listener)
        self.listener = None

        if candidate.inbound:
            log_event(
                "TCP holepunch",
                f"accepted connection from {short_addr(candidate.peer)}",
            )
        else:
            log_event("TCP holepunch", f"connected to {short_addr(candidate.peer)}")
        log_event("TCP verify", tcp_verify_command(candidate.sock))

    def schedule_retry(self, now: float) -> None:
        self.next_connect = now + max(self.interval, 1.0)

    def _start_connect(self, now: float) -> None:
        assert self.peer is not None
        try:
            self.connector = make_tcp_connector(self.bind_addr, self.peer)
            self.connect_attempt += 1
            self.connector_expires_at = now + self.connect_timeout
            self.connector_peer = self.peer
            self.connector_started_at = now
            log_event(
                "TCP holepunch",
                f"connect attempt #{self.connect_attempt}: "
                f"{socket_addr(self.connector)} -> {short_addr(self.peer)} "
                f"timeout={self.connect_timeout:.3f}s; "
                f"listener={self.listener_status()}",
            )
        except OSError as err:
            log_event(
                "TCP holepunch",
                f"connect setup to {short_addr(self.peer)} failed: {err}",
            )
            self.next_connect = now + max(self.interval, 1.0)
        else:
            self.next_connect = now + self.interval

    def _reopen_listener(self) -> None:
        try:
            self.listener = make_tcp_listener(self.bind_addr)
        except OSError as err:
            log_event("TCP listen", f"setup failed: {err}")
            self.listener = None
            return
        log_event("TCP listen", f"reopened on {socket_addr(self.listener)}")


def send_tcp_json(sock: socket.socket, message: dict[str, Any]) -> None:
    sock.sendall(encode_json(message) + b"\n")


# Test chat protocol layered on top of an established TCP connection.
@dataclass
class TestChat:
    config: PeerConfig
    buffer: bytes = b""

    def reset(self) -> None:
        self.buffer = b""

    def send_hello(self, sock: socket.socket) -> None:
        send_tcp_json(
            sock,
            {
                "type": "hello",
                "session": self.config.session,
                "name": self.config.name,
                "time": time.time(),
            },
        )

    def send_chat(self, sock: socket.socket, text: str) -> None:
        send_tcp_json(
            sock,
            {
                "type": "chat",
                "session": self.config.session,
                "name": self.config.name,
                "text": text,
                "time": time.time(),
            },
        )

    def receive(self, data: bytes) -> None:
        self.buffer += data
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            message = decode_json(line)
            if message is None or message.get("session") != self.config.session:
                continue
            message_type = message.get("type")
            sender = message.get("name", "peer")
            if message_type == "hello":
                log_event("TCP chat", f"hello from {sender}")
            elif message_type == "chat":
                text = message.get("text")
                if isinstance(text, str):
                    print(f"{sender}> {text}", flush=True)


@dataclass
class RendezvousTarget:
    peer: Address
    start_at: float
    close_connector_reason: Optional[str] = None
    log_kind: Optional[str] = None
    log_message: Optional[str] = None
    accept_sender_id: Optional[str] = None


# UDP rendezvous lobby and mailbox client.
@dataclass
class RendezvousClient:
    server: Optional[Address]
    session: str
    next_register: float = 0.0
    last_observed: Optional[tuple[Any, Any]] = None
    lobby_peers: dict[str, Address] = field(default_factory=dict)
    invited_ids: set[str] = field(default_factory=set)
    self_id: Optional[str] = None

    def maybe_register(
        self,
        sock: socket.socket,
        tcp_port: int,
        now: float,
        verbose: bool,
    ) -> None:
        if self.server is None or now < self.next_register:
            return

        send_json(
            sock,
            self.server,
            {
                "type": "register",
                "session": self.session,
                "tcp_port": tcp_port,
            },
        )
        if verbose:
            log_event(
                "UDP rendezvous",
                f"sent register to {short_addr(self.server)} advertising TCP "
                f"{tcp_port}",
            )
        self.next_register = now + 1.0

    def reset_registration_timer(self) -> None:
        self.next_register = 0.0

    def invite(self, sock: socket.socket, target_id: str) -> None:
        self.invited_ids.add(target_id)
        if self.server is None:
            log_event("UDP mailbox", "not invited: no rendezvous server configured")
            return
        send_json(
            sock,
            self.server,
            {
                "type": "invite",
                "session": self.session,
                "to": target_id,
            },
        )
        log_event("UDP mailbox", f"sent invite to {target_id}")

    def accept(self, sock: socket.socket, target_id: str) -> None:
        if self.server is None:
            return
        send_json(
            sock,
            self.server,
            {
                "type": "accept",
                "session": self.session,
                "to": target_id,
            },
        )
        log_event("UDP mailbox", f"accepted invite from {target_id}")

    def handle_message(
        self,
        sock: socket.socket,
        message: dict[str, Any],
        now: float,
        auto_connect: bool,
        connect_id: Optional[str],
        has_tcp_connection: bool,
        has_active_peer: bool,
        listener_status: str,
    ) -> Optional[RendezvousTarget]:
        if message.get("session") != self.session:
            return None

        message_type = message.get("type")
        if message_type == "observed":
            self._handle_observed(message)
            return None
        if message_type == "lobby":
            return self._handle_lobby(
                sock,
                message,
                now,
                auto_connect,
                connect_id,
                has_tcp_connection,
                has_active_peer,
                listener_status,
            )
        if message_type in {"invite", "accept"}:
            return self._handle_mailbox(message, listener_status)
        return None

    def _handle_observed(self, message: dict[str, Any]) -> None:
        observed = message.get("addr")
        if isinstance(observed, list) and len(observed) == 2:
            observed_key = (observed[0], observed[1])
            if observed_key != self.last_observed:
                log_event(
                    "UDP rendezvous",
                    f"observed us as {observed[0]}:{observed[1]}",
                )
                self.last_observed = observed_key
        observed_self = message.get("self")
        if isinstance(observed_self, str) and observed_self != self.self_id:
            self.self_id = observed_self
            log_event("UDP lobby", f"our endpoint id is {self.self_id}")

    def _handle_lobby(
        self,
        sock: socket.socket,
        message: dict[str, Any],
        now: float,
        auto_connect: bool,
        connect_id: Optional[str],
        has_tcp_connection: bool,
        has_active_peer: bool,
        listener_status: str,
    ) -> Optional[RendezvousTarget]:
        peers = message.get("peers")
        if not isinstance(peers, list):
            return None

        target: Optional[RendezvousTarget] = None
        for peer_info in peers:
            if not isinstance(peer_info, dict):
                continue
            peer_id = peer_info.get("id")
            peer_addr = peer_info.get("addr")
            if (
                not isinstance(peer_id, str)
                or not isinstance(peer_addr, list)
                or len(peer_addr) != 2
            ):
                continue

            peer_endpoint = (peer_addr[0], int(peer_addr[1]))
            if self.lobby_peers.get(peer_id) != peer_endpoint:
                self.lobby_peers[peer_id] = peer_endpoint
                log_event(
                    "UDP lobby",
                    f"peer {peer_id} advertises TCP {short_addr(peer_endpoint)}",
                )

            if (
                auto_connect
                and peer_id not in self.invited_ids
                and not has_tcp_connection
            ):
                self.invite(sock, peer_id)
                if not has_active_peer and target is None:
                    target = RendezvousTarget(peer=peer_endpoint, start_at=now)

            if connect_id == peer_id and peer_id not in self.invited_ids:
                self.invite(sock, peer_id)
                target = RendezvousTarget(
                    peer=peer_endpoint,
                    start_at=now,
                    close_connector_reason=f"--connect switching to {peer_id}",
                    log_kind="TCP holepunch",
                    log_message=(
                        f"--connect target {peer_id}: peer={short_addr(peer_endpoint)} "
                        f"start_delay=0.000s; listener={listener_status}"
                    ),
                )
        return target

    def _handle_mailbox(
        self,
        message: dict[str, Any],
        listener_status: str,
    ) -> Optional[RendezvousTarget]:
        sender_id = message.get("from")
        peer_info = message.get("peer")
        if not isinstance(sender_id, str) or not isinstance(peer_info, dict):
            return None
        peer_addr = peer_info.get("addr")
        if not isinstance(peer_addr, list) or len(peer_addr) != 2:
            return None

        peer = (peer_addr[0], int(peer_addr[1]))
        start_at = time.monotonic() + (message.get("start_delay_ms", 0) / 1000.0)
        message_type = message.get("type")
        log_message = (
            f"{message_type} from {sender_id}; TCP peer {short_addr(peer)} "
            f"start_at_in={max(0.0, start_at - time.monotonic()):.3f}s; "
            f"listener={listener_status}"
        )
        return RendezvousTarget(
            peer=peer,
            start_at=start_at,
            close_connector_reason=f"{message_type} switching peer",
            log_kind="UDP mailbox",
            log_message=log_message,
            accept_sender_id=sender_id if message_type == "invite" else None,
        )


def run_peer(args: argparse.Namespace) -> int:
    control_sock = make_udp_socket(args.bind)
    control_sock.setblocking(False)
    local_addr = control_sock.getsockname()
    name = args.name or default_name()
    start_at = time.monotonic() + args.start_delay
    manual_peer = (
        resolve_endpoint(args.peer, control_sock.family, socket.SOCK_STREAM)
        if args.peer
        else None
    )
    rendezvous_addr = (
        resolve_endpoint(args.rendezvous, control_sock.family)
        if args.rendezvous
        else None
    )
    config = PeerConfig(name=name, session=LOBBY)
    chat = TestChat(config)
    puncher = TcpPuncher(local_addr, args.interval, start_at)
    rendezvous = RendezvousClient(rendezvous_addr, config.session)
    if manual_peer is not None:
        puncher.set_peer(manual_peer, start_at)

    log_event(
        "bind",
        f"UDP control and TCP holepunch port {short_addr(local_addr)} as {name}",
    )
    assert puncher.listener is not None
    log_event("TCP listen", f"opened on {socket_addr(puncher.listener)}")
    log_peer_commands()

    stun_servers = (
        args.stun if args.stun else ([] if args.skip_stun else [DEFAULT_STUN])
    )
    run_peer_stun_probes(control_sock, stun_servers, args.timeout, puncher.tcp_port)

    if manual_peer is not None:
        log_event("TCP manual", f"peer endpoint {short_addr(manual_peer)}")
    if rendezvous.server is not None:
        log_event(
            "UDP rendezvous",
            f"server {short_addr(rendezvous.server)} lobby={LOBBY}",
        )
    if puncher.peer is None and rendezvous.server is None:
        log_event(
            "TCP listen",
            "no peer or rendezvous configured; waiting for inbound connections",
        )

    end_at = time.monotonic() + args.duration if args.duration > 0 else None
    read_stdin = True

    def apply_rendezvous_target(target: RendezvousTarget) -> None:
        puncher.set_peer(
            target.peer,
            target.start_at,
            close_connector_reason=target.close_connector_reason,
        )
        if target.log_kind is not None and target.log_message is not None:
            log_event(target.log_kind, target.log_message)
        if target.accept_sender_id is not None:
            rendezvous.accept(control_sock, target.accept_sender_id)

    def reset_tcp_connection(reason: str) -> None:
        puncher.reset_connection(reason)
        chat.reset()
        rendezvous.reset_registration_timer()

    def complete_connection(candidate: TcpCandidate) -> None:
        try:
            chat.send_hello(candidate.sock)
        except OSError as hello_err:
            close_socket(candidate.sock)
            if candidate.inbound:
                log_event(
                    "TCP holepunch",
                    f"accepted connection but hello failed: {hello_err}",
                )
            else:
                log_event("TCP holepunch", f"connected but hello failed: {hello_err}")
                puncher.schedule_retry(time.monotonic())
            return
        puncher.adopt_connection(candidate)

    while True:
        now = time.monotonic()
        if end_at is not None and now >= end_at:
            return 0

        if not puncher.connected:
            rendezvous.maybe_register(
                control_sock, puncher.tcp_port, now, args.verbose
            )

        puncher.tick(now)

        timeout = 0.1
        if end_at is not None:
            timeout = max(0.0, min(timeout, end_at - now))
        inputs: list[socket.socket | TextIO] = [control_sock]
        inputs.extend(puncher.read_sockets())
        if read_stdin:
            inputs.append(sys.stdin)
        outputs = puncher.write_sockets()
        readable, writable, _errored = select.select(inputs, outputs, [], timeout)

        if puncher.connector is not None and puncher.connector in writable:
            candidate = puncher.connector_ready(time.monotonic())
            if candidate is not None:
                complete_connection(candidate)

        if not readable:
            continue

        if sys.stdin in readable:
            text = sys.stdin.readline()
            if text == "":
                read_stdin = False
            else:
                text = text.rstrip("\n")
                if text.startswith("/connect "):
                    target_id = text.split(maxsplit=1)[1]
                    rendezvous.invite(control_sock, target_id)
                    peer_endpoint = rendezvous.lobby_peers.get(target_id)
                    if peer_endpoint is not None:
                        puncher.set_peer(
                            peer_endpoint,
                            time.monotonic(),
                            close_connector_reason=(
                                f"manual connect switching to {target_id}"
                            ),
                        )
                        log_event(
                            "TCP holepunch",
                            f"manual connect target {target_id}: "
                            f"peer={short_addr(peer_endpoint)} "
                            f"start_delay=0.000s; "
                            f"listener={puncher.listener_status()}",
                        )
                    else:
                        log_event(
                            "TCP holepunch",
                            f"manual connect target {target_id} is not in current lobby",
                        )
                    readable.remove(sys.stdin)
                    continue
                if text == "/list":
                    if not rendezvous.lobby_peers:
                        log_event("UDP lobby", "no peers advertising")
                    for peer_id, peer_endpoint in sorted(
                        rendezvous.lobby_peers.items()
                    ):
                        log_event(
                            "UDP lobby",
                            f"peer {peer_id} advertises TCP {short_addr(peer_endpoint)}",
                        )
                    readable.remove(sys.stdin)
                    continue
                if text == "/help":
                    log_peer_commands()
                    readable.remove(sys.stdin)
                    continue
                tcp_sock = puncher.established
                if tcp_sock is None:
                    log_event("TCP chat", "not sent: no TCP connection yet")
                elif text:
                    try:
                        chat.send_chat(tcp_sock, text)
                    except OSError as err:
                        reset_tcp_connection(f"send failed: {err}")
            readable.remove(sys.stdin)

        listener = puncher.listener
        if listener is not None and listener in readable:
            readable.remove(listener)
            candidate = puncher.accept_ready()
            if candidate is not None:
                complete_connection(candidate)

        tcp_sock = puncher.established
        if tcp_sock is not None and tcp_sock in readable:
            readable.remove(tcp_sock)
            try:
                data = tcp_sock.recv(4096)
            except BlockingIOError:
                data = b""
            except OSError as err:
                reset_tcp_connection(f"receive failed: {err}")
                data = b""

            if data == b"" and puncher.established is not None:
                reset_tcp_connection("peer disconnected")
            elif data:
                chat.receive(data)

        if control_sock not in readable:
            continue

        try:
            data, _addr = control_sock.recvfrom(2048)
        except BlockingIOError:
            continue

        message = decode_json(data)
        if message is None:
            continue

        target = rendezvous.handle_message(
            control_sock,
            message,
            time.monotonic(),
            args.auto_connect,
            args.connect,
            puncher.connected,
            puncher.peer is not None,
            puncher.listener_status(),
        )
        if target is not None:
            apply_rendezvous_target(target)


def add_bind_arg(parser: argparse.ArgumentParser, default: str, help_text: str) -> None:
    parser.add_argument(
        "--bind",
        default=default,
        help=f"{help_text} (default: {default})",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")

    stun_parser = subparsers.add_parser(
        "stun",
        help="send STUN binding requests and print the mapped endpoint",
    )
    add_bind_arg(stun_parser, DEFAULT_BIND, "local UDP bind endpoint")
    stun_parser.add_argument(
        "--stun",
        action="append",
        default=[DEFAULT_STUN],
        help="STUN UDP server host:port",
    )
    stun_parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="STUN response timeout in seconds",
    )
    stun_parser.set_defaults(func=run_stun)

    peer_parser = subparsers.add_parser("peer", help="run a TCP hole-punch peer")
    add_bind_arg(peer_parser, DEFAULT_BIND, "local UDP control and TCP punch endpoint")
    peer_parser.add_argument(
        "--name", help="local peer name used in diagnostic packets"
    )
    peer_parser.add_argument("--peer", help="manual peer TCP endpoint host:port")
    peer_parser.add_argument(
        "--rendezvous",
        default=DEFAULT_RENDEZVOUS,
        help=f"rendezvous UDP endpoint host:port (default: {DEFAULT_RENDEZVOUS})",
    )
    peer_parser.add_argument(
        "--connect",
        help="rendezvous endpoint id to invite once it appears in the lobby",
    )
    peer_parser.add_argument(
        "--auto-connect",
        action="store_true",
        help="invite the first peer seen in the rendezvous lobby",
    )
    peer_parser.add_argument(
        "--stun",
        action="append",
        default=[],
        help="STUN UDP server host:port",
    )
    peer_parser.add_argument(
        "--skip-stun",
        action="store_true",
        help="do not run the default STUN probe",
    )
    peer_parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="STUN response timeout in seconds",
    )
    peer_parser.add_argument(
        "--interval",
        type=float,
        default=0.25,
        help="seconds between punch packets",
    )
    peer_parser.add_argument(
        "--start-delay",
        type=float,
        default=0.0,
        help="delay before manual punch packets",
    )
    peer_parser.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="exit after this many seconds; 0 means run forever",
    )
    peer_parser.add_argument(
        "--verbose",
        action="store_true",
        help="log repeated rendezvous heartbeat messages",
    )
    peer_parser.set_defaults(func=run_peer)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return 2

    try:
        return args.func(args)
    except KeyboardInterrupt:
        log("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
