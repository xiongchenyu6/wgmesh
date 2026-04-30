# wgmesh

**English** · [简体中文](./README.zh-CN.md)

> **Zero-config WireGuard mesh for NixOS fleets. `nixos-rebuild switch` and the mesh is up.**

No key generation. No enrollment files. No `tailscale up` interactive step on
every node. No web UI to click through. Add the agent module to a host, deploy,
append the host's public SSH line to the coord's allowlist — that's the entire
onboarding. The whole thing is declarative, kernel-WireGuard-fast, and small
enough to run on a 128 MB router. Written in Rust.

[![Tests](https://img.shields.io/badge/tests-43%20passing-brightgreen)](#tests)
[![License](https://img.shields.io/badge/license-MIT-blue)](#license)
[![NixOS](https://img.shields.io/badge/NixOS-first--class-5277c3)](#nixos-deployment)

---

## Why?

Most WireGuard mesh tools either (a) require an account at someone else's SaaS,
(b) ship their own PKI you have to babysit, or (c) push you toward a userspace
WireGuard implementation that's slower and heavier than the kernel module. All
of them require some kind of per-node "onboarding" step that doesn't fit
declarative-OS workflows.

wgmesh's design goal is **the fastest possible mesh deployment under NixOS**.
Every other property follows from that.

- **Pure declarative deployment.** Two first-party NixOS modules
  (`services.wgmesh-coord`, `services.wgmesh`). Add the agent module to every
  host in your flake, `nixos-rebuild switch`, done — there is no interactive
  onboarding step.
- **No key management at all.** Each node's WireGuard keypair is *derived*
  from `/etc/ssh/ssh_host_ed25519_key` using the same algorithm libsodium
  uses (`crypto_sign_ed25519_sk_to_curve25519`). The host key your NixOS
  install already has *is* the WireGuard identity. Composes naturally with
  sops-nix / agenix because there's nothing extra to encrypt.
- **Onboarding = appending a line.** Bring up a new node → grab its
  `ssh-ed25519 …` pubkey (one command, `ssh-keygen -y`) → append to coord's
  `authorized_signers` → `systemctl reload wgmesh-coord`. No invite tokens,
  no expiring credentials, no UI flows.
- **Coord on a public VPS doubles as the relay.** Direct P2P is preferred
  and used when reachable; anything that can't go direct flows through the
  coordinator's wg0 transparently. No DERP infrastructure to operate.
- **Small.** Agent: 2.7 MB on disk, ~3.5 MB RSS at idle. Fits on a 128 MB
  OpenWrt-class node.

---

## Architecture

```
              ┌───────────────────────────┐
              │   Coordinator (public VPS)│
              │   ─────────────────────   │
              │   HTTP API: /register     │
              │              /peers       │
              │   wg0 hub:  10.42.0.1/16  │
              └───────────┬───────────────┘
                          │  signed HTTPS  +  UDP/51820
              ┌───────────┼───────────────┐
              ▼           ▼               ▼
          ┌───────┐   ┌───────┐       ┌───────┐
          │Node A │   │Node B │       │Node C │
          │ NAT   │   │ NAT   │       │ public│
          └───┬───┘   └───┬───┘       └───┬───┘
              │           │               │
              └───┬───────┴───────┬───────┘
                  └── direct WG ──┘
                (relay-via-coord when direct fails)
```

The coord runs HTTP for control + a kernel WireGuard interface for data.
Every agent's wg0 has the coord installed as a peer with
`AllowedIPs = mesh_cidr` (the catch-all). When two agents establish a direct
handshake, the agent rewrites that peer's `AllowedIPs` to `<peer>/32` —
WireGuard's longest-prefix-match routes their traffic point-to-point. When a
direct path is broken, the peer is removed from wg0; its `/32` no longer
exists locally, so traffic naturally falls back to coord's `/16`. No
extra routing daemon, no userland forwarding.

---

## The interesting bit: probe-promote-demote

A naive design — "add the peer with `AllowedIPs = peer.mesh/32` and hope" —
black-holes traffic when the direct connection fails: the `/32` claims the
route locally and beats the coord's `/16`. wgmesh sidesteps that:

```
                     handshake within 60s
            ┌─────┐  ───────────────────►  ┌───────┐
unknown ─►  │PROB │                        │DIRECT │
            │ING  │  ◄───────────────────  │       │
            └──┬──┘   handshake stale 5min └───────┘
               │
   60s no handshake
               ▼
            ┌─────┐
            │RELAY│  ───── retry after backoff ─────► PROBING
            └─────┘   (5 min → 30 min cap, 2× each)
```

| State    | wg0 peer entry                     | Effect on routing               |
|----------|------------------------------------|---------------------------------|
| PROBING  | endpoint set, **`AllowedIPs = []`**| doesn't intercept routing       |
| DIRECT   | endpoint + `AllowedIPs = peer/32`  | beats coord's `/16`, P2P        |
| RELAY    | not in wg0                         | falls through coord's `/16`     |

Empty `AllowedIPs` while probing is the trick: the kernel still attempts
handshakes, but the entry doesn't claim any routes, so the relay path stays
live. Once a handshake lands, we promote to `/32` atomically.

---

## Quick start

### NixOS: use the host key you already have

> Every NixOS host with `services.openssh.enable = true` already has
> `/etc/ssh/ssh_host_ed25519_key`. wgmesh derives the WireGuard keypair
> from it on the fly. **You never run `ssh-keygen`. You never manage a
> WireGuard private key.**

```nix
# coordinator (public VPS)
{
  imports = [ wgmesh.nixosModules.coordinator ];
  services.openssh.enable = true;        # provides the host key
  services.wgmesh-coord = {
    enable                = true;
    meshCidr              = "10.42.0.0/16";
    endpoint              = "vps.example.com:51820";   # public WG UDP host:port
    authorizedSignersPath = "/etc/wgmesh/authorized_signers";
    openFirewall          = true;
  };
  services.coturn = { enable = true; listening-port = 3478; no-tls = true;
    no-dtls = true; use-auth-secret = false; no-auth = true; };
  networking.firewall.allowedUDPPorts = [ 3478 ];
}
```

```nix
# every mesh node
{
  imports = [ wgmesh.nixosModules.agent ];
  services.openssh.enable = true;        # provides the host key
  services.wgmesh = {
    enable      = true;
    coordinator = "https://mesh.example.com:8443";
    stunServer  = "stun.example.com:3478";
  };
}
```

Onboarding a new node is a single pipe — the host key is read from disk,
nothing is generated:

```sh
# read the existing public host key on the new node, append to coord's allowlist
ssh node-x 'ssh-keygen -y -f /etc/ssh/ssh_host_ed25519_key' \
  | ssh coord 'cat >> /etc/wgmesh/authorized_signers \
               && systemctl reload wgmesh-coord'
```

The new node registers on its next reconcile tick and is reachable from the
rest of the mesh.

### Try the conversion (no NixOS, no setup)

`ssh-to-wg` mirrors `ssh-to-age`'s CLI: pipe any SSH public-key stream into
it and get the WG public key out. Useful as a sanity check or when scripting
allowlists:

```sh
# any host that already has an ed25519 SSH key (your own machine, GitHub, …)
ssh-keyscan some.nixos.host | nix run github:xiongchenyu6/wgmesh#ssh-to-wg
# → vknTxwj0J8f14zUlzjQxUJoiVAOuEdDgeMVORQT24yE=
```

### Verify without deploying

Want to confirm everything compiles and the protocol works before pointing
at production hosts? Run the workspace tests — they cover signing, key
derivation, the probe state machine, and a real coord-server round-trip
(register → /peers → re-register) end-to-end:

```sh
cd rust && cargo test --workspace        # 44 tests pass
```

---

## Deploying a fleet

Because everything is declarative, a real fleet is just a normal NixOS
flake. Here's a complete one-VPS-plus-N-agents setup:

```nix
{
  inputs.nixpkgs.url  = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.wgmesh.url   = "github:freemanxiong/wgmesh";

  outputs = { self, nixpkgs, wgmesh }:
  let
    agentModule = name: { config, ... }: {
      networking.hostName  = name;
      services.openssh.enable = true;
      services.wgmesh = {
        enable      = true;
        coordinator = "https://mesh.example.com:8443";
        stunServer  = "stun.example.com:3478";
      };
    };
    mkAgent = name: nixpkgs.lib.nixosSystem {
      system  = "x86_64-linux";
      modules = [ wgmesh.nixosModules.agent (agentModule name) ];
    };
  in {
    nixosConfigurations = {
      coord = nixpkgs.lib.nixosSystem {
        system  = "x86_64-linux";
        modules = [
          wgmesh.nixosModules.coordinator
          { networking.hostName = "coord";
            services.openssh.enable = true;
            services.wgmesh-coord = {
              enable                = true;
              meshCidr              = "10.42.0.0/16";
              endpoint              = "vps.example.com:51820";
              authorizedSignersPath = "/etc/wgmesh/authorized_signers";
              openFirewall          = true;
            };
            services.coturn = {
              enable = true; listening-port = 3478;
              no-tls = true; no-dtls = true;
              use-auth-secret = false; no-auth = true;
            };
            networking.firewall.allowedUDPPorts = [ 3478 ];
          }
        ];
      };
      node-a = mkAgent "node-a";
      node-b = mkAgent "node-b";
      node-c = mkAgent "node-c";
      # ...add as many as you like
    };
  };
}
```

To bring the whole mesh up:

```sh
# 1. Deploy. Each host's NixOS rebuild starts wgmesh-{coord,agent}.
nixos-rebuild switch --flake .#coord  --target-host coord.example.com
nixos-rebuild switch --flake .#node-a --target-host node-a.example.com
nixos-rebuild switch --flake .#node-b --target-host node-b.example.com
nixos-rebuild switch --flake .#node-c --target-host node-c.example.com

# 2. Authorize each node on the coord (append SSH host pubkeys).
ssh node-a 'ssh-keygen -y -f /etc/ssh/ssh_host_ed25519_key' \
  | ssh coord 'cat >> /etc/wgmesh/authorized_signers'
ssh node-b 'ssh-keygen -y -f /etc/ssh/ssh_host_ed25519_key' \
  | ssh coord 'cat >> /etc/wgmesh/authorized_signers'
ssh node-c 'ssh-keygen -y -f /etc/ssh/ssh_host_ed25519_key' \
  | ssh coord 'cat >> /etc/wgmesh/authorized_signers'
ssh coord 'systemctl reload wgmesh-coord'
```

Within ~30 s the agents finish their first reconcile tick, the kernel
WireGuard interfaces come up, and `node-a` can ping `node-b` over
`10.42.0.x`. No interactive `tailscale up`, no invitation file
distribution, no admin UI.

Adding a new node later is exactly two commands: `nixos-rebuild` it, then
append + reload. **There is no other state.** Lose the coord VPS? Restore
`/var/lib/wgmesh-coord/state.json` from backup; mesh IPs come back stable.

---

## How does it compare?

At-a-glance:

|                            | Tailscale / Headscale | Innernet         | Nebula        | Netmaker       | **wgmesh**                    |
|----------------------------|-----------------------|------------------|---------------|----------------|-------------------------------|
| WireGuard transport        | userspace             | kernel           | own protocol  | kernel         | **kernel**                    |
| Identity                   | tailnet key (managed) | CA-issued cert   | CA-issued cert| node key (DB)  | **SSH host key derivation**   |
| Onboarding                 | `tailscale up` (OAuth)| invite file (TTL)| signed cert   | UI / API token | append `ssh-ed25519 …` line   |
| Hub-and-spoke fallback     | DERP relay fleet      | none             | lighthouses   | yes            | **coord doubles as relay**    |
| Admin UI                   | yes                   | no               | no            | yes            | no                            |
| ACLs / segmentation        | yes                   | yes              | yes           | yes            | no                            |
| Mobile clients             | yes                   | no               | no            | partial        | no                            |
| Single-binary control plane| no (DB + DERP)        | server + DB      | lighthouse(s) | server + DB    | **single binary, JSON file**  |
| NixOS module               | community             | community        | community     | community      | **first-party**               |
| Agent binary size          | ~30 MB                | ~5 MB            | ~10 MB        | ~15 MB         | **2.7 MB**                    |
| Source size (LoC)          | hundreds of k         | ~10 k            | ~30 k         | tens of k      | **~2.5 k**                    |

Sizes for non-wgmesh projects are approximate orders of magnitude (vary
with build flags and version); wgmesh numbers are measured on the binaries
this repo produces today.

Below is the honest narrative version.

### vs. Tailscale / Headscale

Tailscale is the gold standard for usability: MagicDNS, ACLs, SSH-via-tailscale,
mobile clients, an admin UI, and the DERP relay fleet that makes connectivity
"just work" everywhere. If you need any of those features, **use Tailscale**
(or Headscale for self-hosted control).

wgmesh trades all of that for:

- **Kernel WireGuard, not userspace.** Tailscale's data path is `wireguard-go`,
  a userspace implementation. Kernel WG is consistently 2–5× faster on Linux
  for high-throughput links and idles at ~zero CPU. wgmesh never touches
  packets in userspace; the agent only configures the kernel module.
- **Identity = the SSH host key you already have.** No tailnet keys to issue,
  rotate, or store. Onboarding is `echo "ssh-ed25519 …" >> authorized_signers`.
  This composes naturally with sops-nix / agenix because the SSH key is
  already in the secrets pipeline — there is nothing *new* to encrypt.
- **An order of magnitude smaller.** Tailscaled is ~30 MB on disk and uses
  noticeable RAM/CPU under load. wgmesh-agent is 2.7 MB and idles at ~3.5 MB
  RSS. Big deal on a 128 MB router; still nice on a fat server.
- **One binary, one JSON file.** No DB, no DERP fleet, no separate metrics
  service. Coord runs on one VPS; if the box dies, mesh tunnels stay up
  (kernel WG is independent of coord) and you restore from a `state.json`
  backup.
- **Auditable.** ~2,500 lines of Rust + 400 lines of Nix. Read it all in an
  afternoon, fork it, own it.

### vs. Innernet

Innernet is the closest cousin technically — also Rust, also kernel WG. The
split:

- **Identity model.** Innernet uses a CA + time-limited invitation files for
  new nodes. wgmesh uses the existing SSH host key with an allowlist; no
  enrollment file changes hands.
- **Relay.** Innernet has no built-in relay; pairs that can't establish a
  direct WG connection are unreachable. wgmesh's coordinator doubles as a
  relay hub, with transparent direct-shortcut promotion when the link
  improves.
- **Scope.** Innernet has CIDR groups, ACLs, and a more elaborate admin
  CLI. wgmesh has none of that — it's a flat `/16` mesh. Pick Innernet if
  you need segmentation built in; pick wgmesh if you want fewer moving
  parts and you'll layer firewalling outside the mesh.

### vs. Nebula

Nebula (Slack) is its own protocol — not WireGuard. Pure userspace TUN
device, signed-certificate identity model, and a host firewall built in.
Different category, really. Choose Nebula when you need a host firewall
that ships with the mesh and don't care about the kernel-WG perf story.

### vs. Netmaker

Netmaker is a Go-based self-hosted mesh with a web UI and a managed-service
flavor. It's the right choice if you want point-and-click ops and don't mind
running a database. wgmesh is the opposite end: declarative configuration,
no UI, no DB, designed for fleets you already manage as code.

### When wgmesh is the **wrong** choice

- You need **mobile clients** → Tailscale (Headscale).
- You need **ACLs or network segmentation** → Tailscale, Innernet.
- You want an **admin UI** → Netmaker, Tailscale.
- You can't run a **public-IP coord** → no mesh in this space works without
  one for relay fallback.
- You're **not on NixOS** → it'll still build and run, but the project's
  value lives in the NixOS modules and the key-derivation flow.

### When wgmesh is the **right** choice

- You're running **NixOS fleets** (homelab, edge, internal infra) and
  already manage SSH host keys via sops-nix / agenix.
- You want **kernel WireGuard performance** without surrendering control to
  a SaaS, and without standing up DERP-equivalent infrastructure.
- Some of your nodes are **memory-tight** (routers, ARM SBCs, small VPSes).
- You prefer **reading the whole codebase** to trusting a black box with
  your network.

---

## Footprint

| Binary             | Release size | Idle RSS¹ |
|--------------------|--------------|-----------|
| `wgmesh-agent`     | 2.7 MB       | ~3.5 MB   |
| `wgmesh-coord`     | 1.8 MB       | 3.5 MB    |
| `ssh-to-wg`        | 636 KB       | n/a       |
| `wgmesh-smoketest` | 2.1 MB       | n/a       |

¹ `wgmesh-coord` RSS measured directly (`/proc/$pid/status`) on x86_64
Linux 7.0 immediately after startup with no peers registered. Release
profile is `opt-level="z"`, `lto="fat"`, `codegen-units=1`, `strip=true`,
`panic="abort"`.

---

## Protocol

Every `/register` and `/peers` request carries three headers:

| Header              | Value                                          |
|---------------------|------------------------------------------------|
| `X-Sig-Timestamp`   | Unix epoch seconds                             |
| `X-Sig-Pubkey`      | OpenSSH `authorized_keys` line                 |
| `X-Sig-Signature`   | base64 ed25519 signature over the canonical    |

Canonical bytes:

```
<timestamp> "\n" <method> "\n" <path> "\n" sha256_hex(body)
```

The server enforces ±60 s clock skew, looks the parsed pubkey up in
`authorized_signers`, and verifies the ed25519 signature. There is no
nonce store; replays are bounded by the skew window. `/register` is
idempotent and `/peers` is a read.

```
POST /register            (signed)
  { hostname, ssh_public_key, wg_public_key, endpoints[], listen_port }
  → { mesh_ip: "10.42.0.7/16" }

GET  /peers               (signed)
  → { self_pubkey,
      relay: { wg_public_key, endpoint, mesh_ip, mesh_cidr }?,
      peers: [ { hostname, wg_public_key, mesh_ip, endpoints[],
                 listen_port, last_seen }, ... ] }

GET  /healthz             (unauthenticated)
```

---

## Repo layout

```
rust/
  Cargo.toml                            workspace manifest (workspace.dependencies)
  crates/
    wgmesh-core/    api types · request signing · keyderive · STUN client
    wgmesh-wglink/  thin wrapper over `wg` and `ip` (kernel WG management)
    wgmesh-coord/   axum HTTP server + relay hub
    wgmesh-agent/   probe state machine + reconcile loop
    wgmesh-tools/   ssh-to-wg, wgmesh-smoketest
nix/
  coordinator.nix   services.wgmesh-coord NixOS module
  agent.nix         services.wgmesh        NixOS module
flake.nix           rustPlatform.buildRustPackage + nixosModules
examples/           sample NixOS host snippets and coord.json
```

Total: about 2,500 lines of Rust + 400 lines of Nix.

---

## Tests

```sh
cd rust && cargo test --workspace
```

| Suite                 | Tests | What                                    |
|-----------------------|-------|-----------------------------------------|
| `wgmesh-core`         | 13    | api round-trip, sig sign/verify, keyderive invariants |
| `wgmesh-core` (parity)| 1     | derived priv produces same pub as `wg pubkey` |
| `wgmesh-wglink`       | 4     | syncconf rendering, `wg show dump` parsing |
| `wgmesh-coord` (unit) | 11    | config defaults, store IP allocation/persistence |
| `wgmesh-coord` (e2e)  | 5     | register, /peers, signer rejection, healthz |
| `wgmesh-agent`        | 9     | probe state machine (all transitions), LAN filtering |
| **Total**             | **43**|                                         |

The `keyderive_wg_parity` test pipes a derived private key through
`wg pubkey` and asserts the result equals our derived public — the kernel
WireGuard tool itself is the oracle. It auto-skips if `wg`/`ssh-keygen`
aren't on PATH.

---

## Building from source

```sh
# Cargo
cd rust
cargo build --release          # → target/release/{wgmesh-coord,wgmesh-agent,ssh-to-wg,wgmesh-smoketest}

# Nix flake
nix build .#wgmesh             # → result/bin/...
nix develop                    # cargo + rustc + clippy + wireguard-tools + coturn
```

The flake's `postInstall` asserts every expected binary lands in `$out/bin/`,
so a successful build means a complete artifact set.

---

## Security model

- Agent reads `/etc/ssh/ssh_host_ed25519_key`, runs as root with
  `CAP_NET_ADMIN`. The WG private key lives in process memory and the kernel
  WG device — never written to disk by wgmesh except a 0600 tempfile passed
  to `wg set private-key` and unlinked immediately after.
- Coord auth is allowlist-only; there is no enrollment / OOB join flow. To
  add a node, append its `ssh-ed25519 …` line and SIGHUP.
- The coord sees relayed traffic patterns (which pair of nodes is
  exchanging traffic, how much). WG encryption guarantees coord can't read
  payloads. Direct-connected pairs bypass coord entirely.
- Replays are bounded by the ±60 s timestamp window. `/register` is
  idempotent; `/peers` is a read. No nonce store on coord.

---

## Trade-offs and non-goals

- **Single coordinator.** Coord outage doesn't disrupt established WG
  tunnels (kernel WG is independent of coord); only new joins and endpoint
  refresh pause. Restore from a backup of `state.json` if you lose the
  VPS — mesh IPs come back stable.
- **No ACLs.** The mesh is a flat `/16`; everyone can talk to everyone.
  Layer firewalls on top if you need segmentation.
- **No web UI.** Configuration is files; observation is logs and
  `wg show`.
- **IPv4 mesh only** (the overlay; IPv6 endpoints under the WireGuard
  transport are fine).
- **Not a Tailscale replacement.** No MagicDNS, no SSH-via-tailscale, no
  app connector. Just a mesh.

---

## Roadmap

- Coordinated UDP hole-punching for symmetric NATs (currently relies on
  PersistentKeepalive + STUN, which works for cone NATs but not symmetric).
- ACME / Let's Encrypt integration in the coord NixOS module.
- TURN fallback for nodes that can't even reach the coord WG endpoint.

---

## License

MIT. See `LICENSE`.

Built on the shoulders of [WireGuard](https://www.wireguard.com),
[ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek),
[axum](https://github.com/tokio-rs/axum), and the Nix community's
WireGuard kernel module work.
