# btcpunch

`btcpunch` is a small TCP hole-punching prototype. It can probe the public UDP
mapping with STUN, prints the endpoint to share manually, and then tries to
establish a direct TCP connection with a peer whose endpoint you already know.

Once the TCP connection is up, each line typed into one peer is sent to the
other peer.

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

Start both peers without `--peer` to print the endpoint each side should share:

```sh
python3 client.py peer --name alice
python3 client.py peer --name bob
```

Copy the printed `--peer HOST:PORT` value from each side, then restart both
peers with the other's endpoint:

```sh
python3 client.py peer --name alice --peer BOB_PUBLIC_IP:PORT
python3 client.py peer --name bob --peer ALICE_PUBLIC_IP:PORT
```

After the TCP connection is established, type chat lines into either client.

## Useful Commands

Probe the public UDP mapping for a local bind address:

```sh
python3 client.py stun --bind 0.0.0.0:50000
```

Bind the peer to a different local UDP/TCP port:

```sh
python3 client.py peer --bind 0.0.0.0:50001 --name alice
```

Run a peer for a fixed duration:

```sh
python3 client.py peer --duration 60
```

Use `--help` for the full option list.
