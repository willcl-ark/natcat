# btcpunch

`btcpunch` is a small TCP hole-punching prototype. It can probe the public UDP
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
./client.py stun
```

Copy the printed `HOST:PORT` value from each side, then start both peers with
the other's endpoint:

```sh
./client.py peer BOB_PUBLIC_IP:PORT
./client.py peer ALICE_PUBLIC_IP:PORT
```

After the TCP connection is established, type into either client or pipe data
through stdin.

## Useful Commands

Probe the public UDP mapping for a local bind address:

```sh
./client.py stun --bind 0.0.0.0:50000
```

Bind the peer to a different local UDP/TCP port:

```sh
./client.py peer --bind 0.0.0.0:50001 PEER_PUBLIC_IP:PORT
```

Use `--help` for the full option list.
