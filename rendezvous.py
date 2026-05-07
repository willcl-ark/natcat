#!/usr/bin/env python3
# Copyright (c)
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tiny UDP lobby and mailbox server for the hardcoded btcpunch lobby."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import select
import socket
import sys
import time
from typing import Any, Optional


DEFAULT_BIND = "0.0.0.0:3479"
DEFAULT_SESSION = "btcpunch"
JSON_MAGIC = "btcpunch-udp-v1"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

Address = tuple[Any, ...]


def log(message: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} {message}", flush=True)


def log_event(kind: str, message: str) -> None:
    log(f"[{kind}] {message}")


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


def resolve_endpoint(value: str) -> Address:
    host, port = parse_host_port(value)
    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    if not infos:
        raise OSError(f"could not resolve {value}")
    return infos[0][4]


def short_addr(addr: Address) -> str:
    host, port = addr[0], addr[1]
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


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


def base58_encode(data: bytes) -> str:
    value = int.from_bytes(data, "big")
    encoded = ""
    while value:
        value, digit = divmod(value, 58)
        encoded = BASE58_ALPHABET[digit] + encoded

    zeroes = 0
    for byte in data:
        if byte != 0:
            break
        zeroes += 1
    return (BASE58_ALPHABET[0] * zeroes) + (encoded or BASE58_ALPHABET[0])


def endpoint_id(addr: Address, tcp_port: int) -> str:
    ip = socket.inet_pton(
        socket.AF_INET6 if len(addr) == 4 else socket.AF_INET, addr[0]
    )
    version = b"\x06" if len(addr) == 4 else b"\x04"
    data = version + ip + int(addr[1]).to_bytes(2, "big") + tcp_port.to_bytes(2, "big")
    return base58_encode(data)


@dataclass
class RendezvousClient:
    id: str
    addr: Address
    tcp_port: int
    last_seen: float


def client_by_addr(
    clients: dict[str, RendezvousClient], addr: Address
) -> Optional[RendezvousClient]:
    for client in clients.values():
        if client.addr == addr:
            return client
    return None


def peer_message(client: RendezvousClient) -> dict[str, Any]:
    return {
        "id": client.id,
        "addr": [client.addr[0], client.tcp_port],
    }


def send_lobby(
    sock: socket.socket,
    session: str,
    clients: dict[str, RendezvousClient],
    client: RendezvousClient,
) -> None:
    send_json(
        sock,
        client.addr,
        {
            "type": "lobby",
            "session": session,
            "self": client.id,
            "peers": [
                peer_message(peer) for peer in clients.values() if peer.id != client.id
            ],
        },
    )


def run(args: argparse.Namespace) -> int:
    sock = make_udp_socket(args.bind)
    sock.setblocking(False)
    log_event(
        "UDP rendezvous",
        f"bound {short_addr(sock.getsockname())} lobby={DEFAULT_SESSION}",
    )

    sessions: dict[str, dict[str, RendezvousClient]] = {}
    end_at = time.monotonic() + args.duration if args.duration > 0 else None

    while True:
        now = time.monotonic()
        if end_at is not None and now >= end_at:
            return 0

        timeout = 0.2
        if end_at is not None:
            timeout = max(0.0, min(timeout, end_at - now))
        readable, _writable, _errored = select.select([sock], [], [], timeout)
        if not readable:
            continue

        try:
            data, addr = sock.recvfrom(2048)
        except BlockingIOError:
            continue

        message = decode_json(data)
        if message is None:
            continue

        session = DEFAULT_SESSION
        clients = sessions.setdefault(session, {})
        for client_id in list(clients):
            if now - clients[client_id].last_seen > args.expire:
                del clients[client_id]

        message_type = message.get("type")
        if message_type == "register":
            tcp_port = message.get("tcp_port")
            if not isinstance(tcp_port, int) or tcp_port < 0 or tcp_port > 65535:
                continue

            client_id = endpoint_id(addr, tcp_port)
            client = RendezvousClient(
                id=client_id,
                addr=addr,
                tcp_port=tcp_port,
                last_seen=now,
            )
            clients[client_id] = client

            send_json(
                sock,
                addr,
                {
                    "type": "observed",
                    "session": session,
                    "addr": [addr[0], addr[1]],
                    "self": client.id,
                },
            )
            send_lobby(sock, session, clients, client)
            continue

        if message_type not in {"invite", "accept"}:
            continue

        sender = client_by_addr(clients, addr)
        if sender is None:
            continue

        target_id = message.get("to")
        if not isinstance(target_id, str):
            continue
        target = clients.get(target_id)
        if target is None:
            continue

        send_json(
            sock,
            target.addr,
            {
                "type": message_type,
                "session": session,
                "from": sender.id,
                "peer": peer_message(sender),
                "start_delay_ms": args.start_delay_ms,
            },
        )
        log_event(
            "UDP mailbox",
            f"relayed {message_type} in lobby={session}: "
            f"{sender.id} {short_addr(sender.addr)} -> "
            f"{target.id} {short_addr(target.addr)}",
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bind",
        default=DEFAULT_BIND,
        help=f"local UDP bind endpoint (default: {DEFAULT_BIND})",
    )
    parser.add_argument(
        "--expire",
        type=float,
        default=30.0,
        help="seconds before an inactive peer expires",
    )
    parser.add_argument(
        "--start-delay-ms",
        type=int,
        default=500,
        help="suggested punch delay sent to peers",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="exit after this many seconds; 0 means run forever",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return run(args)
    except KeyboardInterrupt:
        log("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
