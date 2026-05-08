#!/usr/bin/env python3
# Copyright (c)
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Minimal STUN binding client used to print the public UDP mapping."""

from __future__ import annotations

import ipaddress
import secrets
import socket
import struct
from typing import Optional

from net import Address


STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_SUCCESS = 0x0101
STUN_MAGIC_COOKIE = 0x2112A442
STUN_XOR_MAPPED_ADDRESS = 0x0020
STUN_MAPPED_ADDRESS = 0x0001


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
        if offset + attr_len > end:
            return None
        value = data[offset : offset + attr_len]
        offset += (attr_len + 3) & ~3

        if attr_type == STUN_XOR_MAPPED_ADDRESS:
            try:
                return decode_stun_address(value, transaction_id, xor=True)
            except ValueError:
                return None
        if attr_type == STUN_MAPPED_ADDRESS:
            try:
                mapped = decode_stun_address(value, transaction_id, xor=False)
            except ValueError:
                mapped = None

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
