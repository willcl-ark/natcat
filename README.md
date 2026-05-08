# natcat

`natcat` is a small TCP hole-punching prototype. It can probe the public UDP
mapping with STUN, prints the endpoint to share manually, and then tries to
establish a direct TCP connection with a peer whose endpoint you already know.

Once the TCP connection is up, bytes from stdin are sent to the other peer and
received bytes are written to stdout.

This has been tested between two peers with no firewall, router, VPN provider
or other configuration required, taking the following approximate packet paths
between peers:

```
Peer A
container -> docker NAT -> host -> router NAT/firewall -> starlink WAN

Peer B
NixOS Container -> NixOS host -> router NAT/firewall -> Obscura VPN -> WAN
```

## Basic Usage

Probe each peer's public mapping:

```sh
./natcat.py stun
```

Copy the printed `HOST:PORT` value from each side, then start both peers with
the other's endpoint:

```sh
./natcat.py peer BOB_PUBLIC_IP:PORT
./natcat.py peer ALICE_PUBLIC_IP:PORT
```

After the TCP connection is established, type into either natcat instance or
pipe data through stdin.

For example, send a PSBT file to a peer:

```sh
cat example.psbt | ./natcat.py peer 203.0.113.10:50000
```

## Useful Commands

Probe the public UDP mapping for a local bind address:

```sh
./natcat.py stun --bind 0.0.0.0:50000
```

Bind the peer to a different local UDP/TCP port:

```sh
./natcat.py peer --bind 0.0.0.0:50001 PEER_PUBLIC_IP:PORT
```

Show reconnect and disconnect logs while connecting to a peer:

```sh
./natcat.py peer --debug PEER_PUBLIC_IP:PORT
```

Use `--help` for the full option list.
