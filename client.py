#!/usr/bin/env python3
# Copyright (c)
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Minimal TCP hole-punch prototype."""

from __future__ import annotations

import argparse
import os
import select
import socket
import sys
import time

from holepunch import TcpPuncher
from net import make_udp_socket, resolve_endpoint, short_addr, socket_addr
from stun import stun_binding


DEFAULT_BIND = "0.0.0.0:50000"
DEFAULT_STUN = "stun.fish.foo:3478"
STUN_TIMEOUT = 2.0


def log(message: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} {message}", file=sys.stderr, flush=True)


def log_event(kind: str, message: str) -> None:
    log(f"[{kind}] {message}")


def run_stun(args: argparse.Namespace) -> int:
    sock = make_udp_socket(args.bind)
    log_event("UDP STUN", f"bound {short_addr(sock.getsockname())}")
    server = resolve_endpoint(DEFAULT_STUN, sock.family)
    try:
        mapped = stun_binding(sock, server, STUN_TIMEOUT)
    except socket.timeout:
        log_event("UDP STUN", f"{DEFAULT_STUN} timed out")
        return 1
    except OSError as err:
        log_event("UDP STUN", f"{DEFAULT_STUN} failed: {err}")
        return 1
    log_event("UDP STUN", f"{DEFAULT_STUN} mapped us as {mapped[0]}:{mapped[1]}")
    return 0


def run_peer(args: argparse.Namespace) -> int:
    control_sock = make_udp_socket(args.bind)
    control_sock.setblocking(False)
    local_addr = control_sock.getsockname()
    peer = resolve_endpoint(args.peer, control_sock.family, socket.SOCK_STREAM)
    puncher = TcpPuncher(local_addr, peer, log_event, args.debug)

    log_event("bind", f"UDP STUN and TCP punch port {short_addr(local_addr)}")
    assert puncher.listener is not None
    log_event("TCP listen", f"opened on {socket_addr(puncher.listener)}")
    log_event("TCP manual", f"peer endpoint {short_addr(peer)}")

    read_stdin = True

    def reset_connection(reason: str) -> None:
        puncher.reset_connection(reason)

    while True:
        now = time.monotonic()

        puncher.tick(now)

        timeout = 0.1

        inputs: list[socket.socket | int] = puncher.read_sockets()
        if read_stdin and puncher.established is not None:
            inputs.append(sys.stdin.fileno())
        outputs = puncher.write_sockets()
        readable, writable, _errored = select.select(inputs, outputs, [], timeout)

        if puncher.connector is not None and puncher.connector in writable:
            candidate = puncher.connector_ready(time.monotonic())
            if candidate is not None:
                puncher.adopt_connection(candidate)

        if not readable:
            continue

        stdin_fd = sys.stdin.fileno()
        if stdin_fd in readable:
            data = os.read(stdin_fd, 4096)
            if data == b"":
                read_stdin = False
            else:
                tcp_sock = puncher.established
                if tcp_sock is not None:
                    try:
                        tcp_sock.sendall(data)
                    except OSError as err:
                        reset_connection(f"send failed: {err}")
            readable.remove(stdin_fd)

        listener = puncher.listener
        if listener is not None and listener in readable:
            readable.remove(listener)
            candidate = puncher.accept_ready()
            if candidate is not None:
                puncher.adopt_connection(candidate)

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
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()


def add_bind_arg(parser: argparse.ArgumentParser, default: str, help_text: str) -> None:
    parser.add_argument(
        "--bind",
        default=default,
        help=f"{help_text} (default: {default})",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(required=True)

    stun_parser = subparsers.add_parser("stun")
    add_bind_arg(stun_parser, DEFAULT_BIND, "local UDP bind endpoint")
    stun_parser.set_defaults(func=run_stun)

    peer_parser = subparsers.add_parser("peer")
    peer_parser.add_argument(
        "peer",
        metavar="HOST:PORT",
    )
    add_bind_arg(peer_parser, DEFAULT_BIND, "local UDP STUN and TCP punch endpoint")
    peer_parser.add_argument(
        "--debug",
        action="store_true",
        help="show reconnect and disconnect logs",
    )
    peer_parser.set_defaults(func=run_peer)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        return args.func(args)
    except KeyboardInterrupt:
        log("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
