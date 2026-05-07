# btcpunch Ideas

## Direct UDP DMs

The current TCP prototype uses the rendezvous server as a blind lobby and
mailbox. A later experiment could try sending invite and accept messages
directly between NATed peers over UDP after both sides learn each other's
observed UDP endpoints from the lobby.

Rough sketch:

- keep the rendezvous server as a directory only;
- clients periodically send small UDP "DM" packets directly to selected peer
  endpoints;
- include an invite token, local TCP punch port, and suggested start time;
- have both clients continue sending direct UDP DMs for a few seconds to open
  NAT mappings;
- if the direct UDP DM succeeds, stop using the server mailbox for that peer;
- then run the TCP punch attempt using the directly exchanged candidate data.

This will not work for every NAT type, but it would make the server less
involved in pairing and may be useful for endpoint-independent UDP mappings.
