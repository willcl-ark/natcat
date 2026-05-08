#!/usr/bin/env python3
# Copyright (c)
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Minimal TCP hole-punch prototype.

Manual flow:

    client.py peer
    # Copy and share the printed STUN endpoint, then run both peers with --peer:
    client.py peer --peer BOB_PUBLIC_IP:PORT
    client.py peer --peer ALICE_PUBLIC_IP:PORT

Once the TCP connection is established, lines typed on stdin are sent to the
peer and displayed on the other side.
"""

from __future__ import annotations

import argparse
import select
import socket
import sys
import time
from typing import TextIO

from holepunch import TcpCandidate, TcpPuncher
from net import make_udp_socket, resolve_endpoint, short_addr, socket_addr
from stun import stun_binding


DEFAULT_BIND = "0.0.0.0:50000"
DEFAULT_STUN = "stun.fish.foo:3478"


def log(message: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} {message}", flush=True)


def log_event(kind: str, message: str) -> None:
    log(f"[{kind}] {message}")


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


def complete_connection(puncher: TcpPuncher, candidate: TcpCandidate) -> None:
    puncher.adopt_connection(candidate)


def run_peer(args: argparse.Namespace) -> int:
    control_sock = make_udp_socket(args.bind)
    control_sock.setblocking(False)
    local_addr = control_sock.getsockname()
    start_at = time.monotonic() + args.start_delay
    peer = (
        resolve_endpoint(args.peer, control_sock.family, socket.SOCK_STREAM)
        if args.peer
        else None
    )
    puncher = TcpPuncher(local_addr, args.interval, start_at, log_event)
    if peer is not None:
        puncher.set_peer(peer, start_at)

    log_event("bind", f"UDP STUN and TCP punch port {short_addr(local_addr)}")
    assert puncher.listener is not None
    log_event("TCP listen", f"opened on {socket_addr(puncher.listener)}")

    stun_servers = (
        args.stun if args.stun else ([] if args.skip_stun else [DEFAULT_STUN])
    )
    run_peer_stun_probes(control_sock, stun_servers, args.timeout, puncher.tcp_port)

    if peer is not None:
        log_event("TCP manual", f"peer endpoint {short_addr(peer)}")
    else:
        log_event(
            "TCP listen",
            "waiting for inbound connections; rerun with --peer HOST:PORT to punch",
        )

    end_at = time.monotonic() + args.duration if args.duration > 0 else None
    read_stdin = True

    def reset_connection(reason: str) -> None:
        puncher.reset_connection(reason)

    while True:
        now = time.monotonic()
        if end_at is not None and now >= end_at:
            return 0

        puncher.tick(now)

        timeout = 0.1
        if end_at is not None:
            timeout = max(0.0, min(timeout, end_at - now))

        inputs: list[socket.socket | TextIO] = puncher.read_sockets()
        if read_stdin:
            inputs.append(sys.stdin)
        outputs = puncher.write_sockets()
        readable, writable, _errored = select.select(inputs, outputs, [], timeout)

        if puncher.connector is not None and puncher.connector in writable:
            candidate = puncher.connector_ready(time.monotonic())
            if candidate is not None:
                complete_connection(puncher, candidate)

        if not readable:
            continue

        if sys.stdin in readable:
            text = sys.stdin.readline()
            if text == "":
                read_stdin = False
            else:
                tcp_sock = puncher.established
                if tcp_sock is None:
                    log_event("TCP chat", "not sent: no TCP connection yet")
                elif text.rstrip("\n"):
                    try:
                        tcp_sock.sendall(text.encode())
                    except OSError as err:
                        reset_connection(f"send failed: {err}")
            readable.remove(sys.stdin)

        listener = puncher.listener
        if listener is not None and listener in readable:
            readable.remove(listener)
            candidate = puncher.accept_ready()
            if candidate is not None:
                complete_connection(puncher, candidate)

        tcp_sock = puncher.established
        if tcp_sock is not None and tcp_sock in readable:
            readable.remove(tcp_sock)
            try:
                data = tcp_sock.recv(4096)
            except BlockingIOError:
                data = b""
            except OSError as err:
                reset_connection(f"receive failed: {err}")
                data = b""

            if data == b"" and puncher.established is not None:
                reset_connection("peer disconnected")
            elif data:
                print(data.decode(errors="replace"), end="", flush=True)


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
    add_bind_arg(peer_parser, DEFAULT_BIND, "local UDP STUN and TCP punch endpoint")
    peer_parser.add_argument("--peer", help="peer TCP endpoint host:port")
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
        help="seconds between punch attempts",
    )
    peer_parser.add_argument(
        "--start-delay",
        type=float,
        default=0.0,
        help="delay before punch attempts",
    )
    peer_parser.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="exit after this many seconds; 0 means run forever",
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
