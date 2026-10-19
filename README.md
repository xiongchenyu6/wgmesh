# wgmesh

**English** · [简体中文](./README.zh-CN.md)

A kernel-WireGuard full mesh for NixOS, assembled from stock modules. There is no
daemon of its own: wgmesh is one NixOS module plus a small patch to
[wgautomesh](https://git.deuxfleurs.fr/Deuxfleurs/wgautomesh).

- `networking.wireguard` creates the interface and one static peer, the
  **relay**, which carries the whole mesh prefix.
- `services.wgautomesh` adds every other node as a `/32` peer, shares endpoints
  by encrypted gossip and LAN broadcast, and punches through NAT by having both
  sides dial the endpoints the relay saw.
- The patch (`nix/wgautomesh-relay-fallback.patch`, setting `relay_fallback`)
  gives a node its `/32` only while its handshake is fresh. A pair that cannot
  connect directly keeps talking through the relay's covering route, and moves
  to the direct path as soon as a handshake succeeds.

Everything is declared in Nix: the node list, the addresses and the keys. A
node joins when it appears in `nodes` on every host and the hosts are rebuilt.

## Usage

```nix
{
  inputs.wgmesh.url = "github:xiongchenyu6/wgmesh";

  # in a NixOS configuration
  imports = [ inputs.wgmesh.nixosModules.default ];

  services.wgmesh = {
    enable = true;
    cidr = "10.42.0.0/24";
    relay = "hub";
    privateKeyFile = "/run/secrets/wireguard";
    gossipSecretFile = "/run/secrets/wgmesh-gossip"; # same on every node
    nodes = {
      hub = { address = "10.42.0.1"; publicKey = "..."; endpoint = "203.0.113.1:51820"; };
      laptop = { address = "10.42.0.20"; publicKey = "..."; };
      desktop = { address = "10.42.0.21"; publicKey = "..."; };
    };
  };
}
```

`hostName` defaults to `networking.hostName` and selects this host's entry in
`nodes`. `relayPrefixes` adds prefixes outside the mesh that the other nodes route
through the relay, for a network the relay is a gateway to. The relay needs a public endpoint and gets `net.ipv4.ip_forward`; the
others only need outbound UDP. The WireGuard port (default 51820) and the gossip
port (1666) are opened in the firewall.

## Limits

- IPv4 overlay, one address per node: no subnet routing.
- Linux only (wgautomesh drives `wg` on the host).
- One relay. Nodes behind symmetric NAT on both sides stay relayed.
- wgautomesh works on a 30 s loop with a 5 min handshake timeout: a new direct
  path takes up to 30 s to settle on both sides, and a peer that vanishes keeps
  its direct route for up to 5 min before falling back to the relay.

## Tests

`nix flake check` runs a four-VM test (`tests/vm.nix`): two nodes on a shared LAN
must connect directly, a third on another LAN must be reached through the relay,
and the relay must hold a `/32` for everyone.

## License

MIT
