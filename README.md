# btcpunch

`btcpunch` is a small TCP hole-punching prototype. It uses UDP for discovery
and coordination, then tries to establish a direct TCP connection between two
peers. Once the TCP connection is up, each line typed into one peer is sent to
the other peer.

The prototype has two main parts:

- `client.py`: runs a peer, probes its public UDP mapping with STUN, joins the
  rendezvous lobby, and attempts the TCP punch.
- `rendezvous.py`: runs a tiny UDP lobby and mailbox server. It records peers
  by their observed UDP address and advertised TCP port, assigns endpoint ids,
  and relays invite/accept messages.

The hardcoded lobby name is `btcpunch`.

## Basic Usage

Start a rendezvous server on a public host:

```sh
python3 rendezvous.py --bind 0.0.0.0:3479
```

Run two peers. By default they use `stun.fish.foo:3479` as the rendezvous
server, so pass `--rendezvous` if you are using your own server:

```sh
python3 client.py peer --name alice --rendezvous RENDEZVOUS_IP:3479
python3 client.py peer --name bob --rendezvous RENDEZVOUS_IP:3479
```

Each peer prints its endpoint id and the ids of peers it sees in the lobby.
Invite a peer by typing this into one client:

```text
/connect ENDPOINT_ID
```

For quick testing, one side can invite the first peer it sees:

```sh
python3 client.py peer --name alice --rendezvous RENDEZVOUS_IP:3479 --auto-connect
python3 client.py peer --name bob --rendezvous RENDEZVOUS_IP:3479
```

After the TCP connection is established, type chat lines into either client.

## Manual Endpoint Exchange

You can manually exchange the public endpoint printed by the STUN probe instead
of using the rendezvous lobby to find peers:

```sh
python3 client.py peer --name alice
python3 client.py peer --name bob
```

Copy the `--peer HOST:PORT` value printed by each side, then restart both
peers with the other's endpoint:

```sh
python3 client.py peer --name alice --peer BOB_PUBLIC_IP:PORT
python3 client.py peer --name bob --peer ALICE_PUBLIC_IP:PORT
```

## Useful Commands

Probe the public UDP mapping for a local bind address:

```sh
python3 client.py stun --bind 0.0.0.0:50000
```

Bind the peer to a different local UDP/TCP port:

```sh
python3 client.py peer --bind 0.0.0.0:50001 --name alice
```

Run either process for a fixed duration:

```sh
python3 rendezvous.py --duration 60
python3 client.py peer --duration 60
```

Use `--help` on either script for the full option list.
