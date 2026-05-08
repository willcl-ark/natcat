#!/usr/bin/env python3
# Copyright (c)
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Core TCP hole-punch state machine."""

from __future__ import annotations

from dataclasses import dataclass
import os
import socket
import time
from typing import Optional

from net import (
    Address,
    make_tcp_connector,
    make_tcp_listener,
    short_addr,
    socket_addr,
)


CONNECT_TIMEOUT = 1.0
PUNCH_INTERVAL = 0.25
RETRY_DELAY = 1.0


def close_socket(sock: Optional[socket.socket]) -> None:
    if sock is not None:
        sock.close()


def tcp_verify_command(sock: socket.socket) -> str:
    local_port = sock.getsockname()[1]
    return f"ss -tnp state established '( sport = :{local_port} or dport = :{local_port} )'"


@dataclass
class TcpCandidate:
    sock: socket.socket
    peer: Address
    inbound: bool


class TcpPuncher:
    def __init__(
        self,
        bind_addr: Address,
        peer: Address,
        log_event,
    ) -> None:
        self.bind_addr = bind_addr
        self.peer = peer
        self.log_event = log_event

        self.listener: Optional[socket.socket] = make_tcp_listener(bind_addr)
        self.connector: Optional[socket.socket] = None
        self.connector_expires_at = 0.0
        self.connector_started_at = 0.0
        self.established: Optional[socket.socket] = None

        self.next_connect = 0.0
        self.connect_attempt = 0

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

    def close_connector(self, reason: str) -> None:
        if self.connector is not None:
            age = time.monotonic() - self.connector_started_at
            self.log_event(
                "TCP holepunch",
                f"{reason}: closing connector {socket_addr(self.connector)} -> "
                f"{short_addr(self.peer)} after {age:.3f}s; "
                f"listener={self.listener_status()}",
            )
        close_socket(self.connector)
        self.connector = None
        self.connector_expires_at = 0.0
        self.connector_started_at = 0.0

    def reset_connection(self, reason: str) -> None:
        self.log_event("TCP holepunch", reason)
        close_socket(self.established)
        self.established = None
        self.close_connector("reset")
        if self.listener is None:
            self._reopen_listener()

    def tick(self, now: float) -> None:
        if self.established is not None:
            return

        if self.connector is not None and now >= self.connector_expires_at:
            self.close_connector(f"connect timed out after {CONNECT_TIMEOUT:.3f}s")
            self.next_connect = now

        if self.connector is None and now >= self.next_connect:
            self._start_connect(now)

    def connector_ready(self, now: float) -> Optional[TcpCandidate]:
        if self.connector is None:
            return None

        err = self.connector.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err == 0:
            candidate_sock = self.connector
            self.connector = None
            self.connector_expires_at = 0.0
            self.connector_started_at = 0.0
            return TcpCandidate(candidate_sock, self.peer, inbound=False)

        self.log_event(
            "TCP holepunch",
            f"connect to {short_addr(self.peer)} failed: {os.strerror(err)}",
        )
        self.close_connector("connect failed")
        self.next_connect = now + RETRY_DELAY
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
            self.log_event(
                "TCP listen",
                f"closing {socket_addr(self.listener)} after {direction}",
            )
        close_socket(self.listener)
        self.listener = None

        if candidate.inbound:
            self.log_event(
                "TCP holepunch",
                f"accepted connection from {short_addr(candidate.peer)}",
            )
        else:
            self.log_event("TCP holepunch", f"connected to {short_addr(candidate.peer)}")
        self.log_event("TCP verify", tcp_verify_command(candidate.sock))

    def _start_connect(self, now: float) -> None:
        try:
            self.connector = make_tcp_connector(self.bind_addr, self.peer)
            self.connect_attempt += 1
            self.connector_expires_at = now + CONNECT_TIMEOUT
            self.connector_started_at = now
            self.log_event(
                "TCP holepunch",
                f"connect attempt #{self.connect_attempt}: "
                f"{socket_addr(self.connector)} -> {short_addr(self.peer)} "
                f"timeout={CONNECT_TIMEOUT:.3f}s; "
                f"listener={self.listener_status()}",
            )
        except OSError as err:
            self.log_event(
                "TCP holepunch",
                f"connect setup to {short_addr(self.peer)} failed: {err}",
            )
            self.next_connect = now + RETRY_DELAY
        else:
            self.next_connect = now + PUNCH_INTERVAL

    def _reopen_listener(self) -> None:
        try:
            self.listener = make_tcp_listener(self.bind_addr)
        except OSError as err:
            self.log_event("TCP listen", f"setup failed: {err}")
            self.listener = None
            return
        self.log_event("TCP listen", f"reopened on {socket_addr(self.listener)}")
