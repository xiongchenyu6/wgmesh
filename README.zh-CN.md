# wgmesh

[English](./README.md) · **简体中文**

> **NixOS 集群的零配置 WireGuard 组网工具。`nixos-rebuild switch` 一下，组网就起来了。**

不用生成密钥、不用分发邀请文件、不用每台机器交互式跑 `tailscale up`、不用点击 Web UI。
把 agent 模块加到主机配置里，部署，把节点的 SSH 公钥追加到协调器的允许列表
——这就是全部接入流程。整个系统是声明式的、内核态 WireGuard 一样快、agent 二进制
小到能塞进 128 MB 内存的边缘节点。Rust 实现。

[![Tests](https://img.shields.io/badge/tests-43%20passing-brightgreen)](#测试)
[![License](https://img.shields.io/badge/license-MIT-blue)](#许可)
[![NixOS](https://img.shields.io/badge/NixOS-first--class-5277c3)](#nixos-部署)

---

## 为什么做这个？

市面上的 WireGuard 组网工具，要么 (a) 强制依赖某家 SaaS，要么 (b) 自带一套 PKI
要你管理证书，要么 (c) 推你用用户态 WireGuard（比内核态慢一截、占用更高）。
而且都需要某种"每节点接入步骤"，跟声明式系统的工作流并不契合。

wgmesh 的设计目标是 **NixOS 下最快速度起一张网**。其它特性都是从这个目标推导出来的。

- **纯声明式部署。** 提供两个一等公民的 NixOS 模块（`services.wgmesh-coord`、
  `services.wgmesh`）。把 agent 模块加到 flake 里每一台主机上，
  `nixos-rebuild switch`，完事——没有任何交互式接入步骤。
- **完全不用管密钥。** 每个节点的 WireGuard 密钥对从 `/etc/ssh/ssh_host_ed25519_key`
  推导出来（用 libsodium 的 `crypto_sign_ed25519_sk_to_curve25519` 算法）。
  系统已经有的 SSH host key **就是** WireGuard 身份。和 sops-nix / agenix
  天然契合，因为没有任何额外的东西需要加密。
- **接入 = 改 flake。** 装好新节点 → 一行命令拿到它的 `ssh-ed25519 …` 公钥
  （`ssh node 'cat /etc/ssh/ssh_host_ed25519_key.pub'`）→ 加到协调器配置的
  `services.wgmesh-coord.authorizedSigners` 列表里 → `nixos-rebuild switch`。
  模块自动重写允许列表文件、自动 SIGHUP coord（`reloadTriggers`）。允许接入
  的节点列表躺在 git 里，不是命令式 side-effect 留下的状态。
- **协调器同时充当中继。** 直接 P2P 能通就用直连；通不了的流量自动走协调器的
  wg0 中继过去。无需运维 DERP 之类的中继基础设施。
- **够小。** Agent 二进制 2.7 MB，空载时 RSS 约 3.5 MB。在 128 MB
  OpenWrt 级别的节点上跑得宽宽松松。

---

## 架构

```
              ┌───────────────────────────┐
              │  协调器 (有公网 IP 的 VPS)  │
              │   ─────────────────────   │
              │   HTTP API: /register     │
              │              /peers       │
              │   wg0 中继: 10.42.0.1/16  │
              └───────────┬───────────────┘
                          │  签名 HTTPS  +  UDP/51820
              ┌───────────┼───────────────┐
              ▼           ▼               ▼
          ┌───────┐   ┌───────┐       ┌───────┐
          │节点 A │   │节点 B │       │节点 C │
          │ NAT   │   │ NAT   │       │ 公网  │
          └───┬───┘   └───┬───┘       └───┬───┘
              │           │               │
              └───┬───────┴───────┬───────┘
                  └─ 直连 WireGuard ┘
              （直连失败时走协调器中继）
```

协调器跑 HTTP 控制面 + 一个内核态 WireGuard 接口做数据面。每个 agent 的 wg0
都把协调器作为一个 peer，`AllowedIPs = mesh_cidr`（默认走它）。
两个 agent 之间一旦直连握手成功，agent 就把对端 peer 的 `AllowedIPs`
改写成 `<peer>/32` —— WireGuard 的最长前缀匹配会让这两台之间的流量直连。
直连失败时，把这个 peer 从 wg0 拿掉；它的 `/32` 路由就消失了，
流量自然回落到协调器的 `/16`。无需额外路由守护进程，无需用户态转发。

---

## 关键设计：探测 → 提升 → 降级

最直白的做法——"加 peer 时 `AllowedIPs = peer.mesh/32`，碰运气"
——会在直连失败时**黑洞流量**：本地 `/32` 路由比协调器的 `/16` 优先，
但 peer 又连不通。wgmesh 用一个状态机绕开这个问题：

```
                     60s 内握手成功
            ┌─────┐  ───────────────────►  ┌───────┐
未知 ─────► │PROB │                        │DIRECT │
            │ING  │  ◄───────────────────  │       │
            └──┬──┘   5 分钟未握手          └───────┘
               │
   60s 内未握手
               ▼
            ┌─────┐
            │RELAY│  ───── 退避后重试 ─────► PROBING
            └─────┘   (5 分钟 → 30 分钟封顶, 每次 ×2)
```

| 状态     | 在 wg0 的表现                       | 路由效果                      |
|----------|-------------------------------------|-------------------------------|
| PROBING  | endpoint 已设置, **`AllowedIPs = []`** | 不抢路由                       |
| DIRECT   | endpoint + `AllowedIPs = peer/32`   | 抢过协调器 `/16`, 直连         |
| RELAY    | 不在 wg0 里                          | 流量走协调器 `/16` 中继        |

PROBING 状态下 `AllowedIPs` 留空是关键：内核仍然会尝试握手，
但这一项不抢任何路由，中继路径不受影响。一旦握手成功，原子地提升为 `/32`。

---

## 快速试用

### NixOS：直接用现成的 SSH host key

> 任何 `services.openssh.enable = true;` 的 NixOS 主机都已经有
> `/etc/ssh/ssh_host_ed25519_key`。wgmesh 直接从它推导 WireGuard 密钥对。
> **你不需要跑 `ssh-keygen`，也不用管理任何 WireGuard 私钥。**

```nix
# 协调器（有公网 IP 的 VPS）
{
  imports = [ wgmesh.nixosModules.coordinator ];
  services.openssh.enable = true;        # 提供 host key
  services.wgmesh-coord = {
    enable    = true;
    meshCidr  = "10.42.0.0/16";
    authorizedSigners = [
      "ssh-ed25519 AAAA... node-a"       # 每行一个节点
      "ssh-ed25519 AAAA... node-b"
    ];
    openFirewall = true;
    # 不用配 endpoint：agent 已经知道 coord 的 hostname
    # （它就是 agent 自己 services.wgmesh.coordinator URL 里的 host），
    # WG 端口由 coord 通过 /peers 广播（默认 51820）。
  };
  services.coturn = { enable = true; listening-port = 3478; no-tls = true;
    no-dtls = true; use-auth-secret = false; no-auth = true; };
  networking.firewall.allowedUDPPorts = [ 3478 ];
}
```

```nix
# 每个 mesh 节点
{
  imports = [ wgmesh.nixosModules.agent ];
  services.openssh.enable = true;        # 提供 host key
  services.wgmesh = {
    enable      = true;
    coordinator = "https://mesh.example.com:8443";
    stunServer  = "stun.example.com:3478";
  };
}
```

接入新节点是声明式两步走：

```sh
# 1. 拿到新节点已有的公钥（只读）。
ssh node-x cat /etc/ssh/ssh_host_ed25519_key.pub
```

```nix
# 2. 把这一行加到 coord 的 NixOS 配置里，rebuild：
services.wgmesh-coord.authorizedSigners = [
  "ssh-ed25519 AAAA... node-a"
  "ssh-ed25519 AAAA... node-b"
  "ssh-ed25519 AAAA... node-x"   # ← 新加的
];
```

```sh
nixos-rebuild switch --flake .#coord --target-host coord.example.com
```

模块自动重渲染 `/etc/wgmesh/authorized_signers`、自动 SIGHUP coord
（靠 `reloadTriggers`）；新节点在下一次 reconcile tick 自动注册。
允许接入的节点列表现在是 git 里的一行，而不是命令式 shell 管道留下的
不可追溯状态。

### 单独验证转换（无需 NixOS、无需任何配置）

`ssh-to-wg` 的 CLI 与 `ssh-to-age` 完全一致：把任何 SSH 公钥流喂给它，输出
对应的 WG 公钥。可以用来快速验证或写脚本生成允许列表：

```sh
# 任何已有 ed25519 SSH key 的主机（你自己的机器、GitHub 等）
ssh-keyscan some.nixos.host | nix run github:xiongchenyu6/wgmesh#ssh-to-wg
# → vknTxwj0J8f14zUlzjQxUJoiVAOuEdDgeMVORQT24yE=
```

### 不部署也想验证一下

想在指向真实主机之前先确认能编、协议没问题？跑 workspace 测试就够了——
覆盖签名、密钥推导、探测状态机，以及一次 coord 服务端的真实注册→`/peers`
→重注册端到端流程：

```sh
cd rust && cargo test --workspace        # 44 个测试通过
```

---

## 部署一整个集群

因为完全声明式，搭一整张实际的网就是一个普通的 NixOS flake。
下面是一个"一台 VPS + N 台 agent"的完整 flake：

```nix
{
  inputs.nixpkgs.url  = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.wgmesh.url   = "github:xiongchenyu6/wgmesh";

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
              enable    = true;
              meshCidr  = "10.42.0.0/16";
              authorizedSigners = [
                "ssh-ed25519 AAAA... node-a"
                "ssh-ed25519 AAAA... node-b"
                "ssh-ed25519 AAAA... node-c"
              ];
              openFirewall = true;
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
      # ...想加多少加多少
    };
  };
}
```

整网上线流程：

```sh
# 1. 先部署 agent，让每台主机的 sshd 自动生成 host key。
nixos-rebuild switch --flake .#node-a --target-host node-a.example.com
nixos-rebuild switch --flake .#node-b --target-host node-b.example.com
nixos-rebuild switch --flake .#node-c --target-host node-c.example.com

# 2. 读出每个节点的公钥（只读），粘到 coord 配置的
#    `authorizedSigners` 列表里。git commit。
for h in node-a node-b node-c; do ssh $h cat /etc/ssh/ssh_host_ed25519_key.pub; done
$EDITOR flake.nix   # 粘进去，提交。

# 3. 部署 coord。模块自动渲染 authorized_signers，
#    reloadTriggers 在 activation 时触发服务 reload。
nixos-rebuild switch --flake .#coord --target-host coord.example.com
```

约 30 秒后 agent 完成首次 reconcile，内核 WireGuard 接口起来，
`node-a` 通过 `10.42.0.x` 就能 ping 到 `node-b`。
没有交互式 `tailscale up`、没有邀请文件分发、没有 UI 操作。

之后加节点：`nixos-rebuild` 装好节点，把它的公钥加到
`authorizedSigners`，再 `nixos-rebuild` 一下 coord 即可。
**整套系统没有别的状态。** 协调器 VPS 挂了？从备份还原
`/var/lib/wgmesh-coord/state.json`，mesh IP 自动还是原来的。

---

## 横向对比

总览：

|                            | Tailscale / Headscale | Innernet         | Nebula        | Netmaker       | **wgmesh**                     |
|----------------------------|-----------------------|------------------|---------------|----------------|--------------------------------|
| WireGuard 实现             | 用户态                | 内核态           | 自有协议      | 内核态         | **内核态**                     |
| 身份                       | tailnet 密钥（托管）  | CA 签发证书      | CA 签发证书   | DB 里的节点密钥 | **从 SSH host key 推导**        |
| 接入方式                   | `tailscale up` (OAuth)| 邀请文件 (有 TTL)| 签名证书      | UI / API token | 追加 `ssh-ed25519 …` 一行       |
| 中继兜底                   | DERP 中继集群         | 无               | lighthouse    | 有             | **协调器同时充当中继**          |
| 管理界面                   | 有                    | 无               | 无            | 有             | 无                             |
| ACL / 网段隔离             | 有                    | 有               | 有            | 有             | 无                             |
| 移动端                     | 有                    | 无               | 无            | 部分           | 无                             |
| 控制面单二进制             | 否（DB + DERP）       | server + DB      | lighthouse(s) | server + DB    | **单二进制 + 一个 JSON 文件**   |
| NixOS 模块                 | 社区维护              | 社区维护         | 社区维护      | 社区维护       | **官方维护**                   |
| Agent 二进制大小           | ~30 MB                | ~5 MB            | ~10 MB        | ~15 MB         | **2.7 MB**                     |
| 源码量 (LoC)               | 几十万                | ~10 k            | ~30 k         | 几万           | **~2.5 k**                     |

非 wgmesh 项目的二进制大小是数量级估算（受编译选项和版本影响），
wgmesh 数字是当前仓库实际产物的精确测量。

下面是诚实点说的对比：

### vs. Tailscale / Headscale

Tailscale 是体验上的标杆：MagicDNS、ACL、SSH-via-tailscale、移动端、
管理 UI、四海皆通的 DERP 中继集群。如果你需要这些，**用 Tailscale**
（自托管控制面就用 Headscale）。

wgmesh 拿这些做交换，换来：

- **内核态 WireGuard，不是用户态。** Tailscale 的数据面是 `wireguard-go`
  这个用户态实现。Linux 内核态 WG 在高吞吐链路上比它快 2–5 倍，空载几乎不
  占 CPU。wgmesh 永远不在用户态碰包；agent 只是在配置内核模块。
- **身份就是你已经有的 SSH host key。** 不用签发、不用轮换、不用储存
  tailnet 密钥。接入流程是 `echo "ssh-ed25519 …" >> authorized_signers`。
  和 sops-nix / agenix 天然契合，因为 SSH 密钥本来就在你的密钥流水线里
  ——**没有任何新东西需要加密**。
- **小一个数量级。** tailscaled 二进制 ~30 MB，负载下 RAM/CPU 也不省。
  wgmesh-agent 是 2.7 MB，空载 RSS ~3.5 MB。在 128 MB 路由器上很重要，
  在大服务器上也舒服。
- **一个二进制 + 一个 JSON 文件。** 没有 DB、没有 DERP 集群、没有指标服务。
  协调器跑在一台 VPS 上；机器挂了，已建立的 mesh 隧道仍然在
  （内核 WG 不依赖协调器），只要从 `state.json` 备份还原即可。
- **可审计。** Rust ~2,500 行 + Nix ~400 行。一个下午读完，fork 走，
  完全是你的。

### vs. Innernet

Innernet（Rust，内核态 WG）从技术上最像。区别：

- **身份模型。** Innernet 用 CA + 限时邀请文件给新节点；wgmesh 用现成的
  SSH host key + 允许列表，没有邀请文件这一步。
- **中继。** Innernet 没有内置中继；直连不通的节点对就连不上。wgmesh 的协调器
  自带中继，并能在直连成功时自动切到直连。
- **覆盖范围。** Innernet 有 CIDR groups、ACL 和更丰富的管理 CLI。wgmesh 啥都
  没有——它就是一张扁平的 `/16`。需要分段就用 Innernet，组件越少越好就用 wgmesh
  并在外面叠防火墙。

### vs. Nebula

Nebula（Slack）是它自己的协议——不是 WireGuard。纯用户态 TUN 设备，
基于签发证书的身份模型，自带主机防火墙。和 wgmesh 不同品类，真要选 Nebula
是因为想要一个开箱带主机防火墙的 mesh，且不在意内核 WG 的性能优势。

### vs. Netmaker

Netmaker 是带 Web UI 的 Go 自托管 mesh，也提供托管服务的味道。
适合要点点点运维、能接受跑数据库的用户。wgmesh 在另一头：声明式配置、
没 UI、没 DB，给"主机配置即代码"的集群准备的。

### wgmesh **不适合**的场景

- 需要**移动端** → Tailscale (Headscale)。
- 需要 **ACL 或网段隔离** → Tailscale、Innernet。
- 需要**管理 UI** → Netmaker、Tailscale。
- **没有公网 IP 的协调器** → 这一类工具都需要一台公网机器做中继兜底。
- **不在 NixOS 上** → 能编能跑，但本项目的核心价值在 NixOS 模块和密钥推导
  这套流程上。

### wgmesh **适合**的场景

- 在跑 **NixOS 集群**（家庭实验室、边缘节点、内部基础设施），SSH host key
  已经走了 sops-nix / agenix 这类管控方式。
- 想要**内核态 WireGuard 性能**，又不想交给 SaaS，也不想为了 DERP-like 中继
  自己搭一套基础设施。
- 部分节点**内存紧张**（路由器、ARM 单板机、小 VPS）。
- 倾向**读完整套代码**再决定要不要把网交给它。

---

## 资源占用

| 二进制              | release 大小 | 空载 RSS¹ |
|---------------------|--------------|-----------|
| `wgmesh-agent`      | 2.7 MB       | ~3.5 MB   |
| `wgmesh-coord`      | 1.8 MB       | 3.5 MB    |
| `ssh-to-wg`         | 636 KB       | 不适用    |
| `wgmesh-smoketest`  | 2.1 MB       | 不适用    |

¹ `wgmesh-coord` 的 RSS 是直接读 `/proc/$pid/status` 测的（x86_64 Linux 7.0，
启动后无任何 peer 注册）。release 编译参数：`opt-level="z"`、`lto="fat"`、
`codegen-units=1`、`strip=true`、`panic="abort"`。

---

## 协议

普通的 HTTP + JSON，ed25519 签名走 header。为什么没用 gRPC，见
[取舍](#取舍--不做的事)。

`/register` 和 `/peers` 都带三个签名头：

| Header              | 内容                                           |
|---------------------|------------------------------------------------|
| `X-Sig-Timestamp`   | Unix 秒级时间戳                                |
| `X-Sig-Pubkey`      | OpenSSH `authorized_keys` 格式的公钥           |
| `X-Sig-Signature`   | 对规范化字节做 ed25519 签名后 base64 编码       |

规范化字节：

```
<timestamp> "\n" <method> "\n" <path> "\n" sha256_hex(body)
```

服务端校验 ±60s 时钟偏移、把解析出来的公钥在 `authorized_signers` 里查一遍、
用 ed25519 验签。没有 nonce 库；重放攻击被 ±60s 窗口限定。`/register` 幂等，
`/peers` 是只读，所以没有 nonce 也安全。

```
POST /register            （需要签名）
  { hostname, ssh_public_key, wg_public_key, endpoints[], listen_port }
  → { mesh_ip: "10.42.0.7/16" }

GET  /peers               （需要签名）
  → { self_pubkey,
      relay: { wg_public_key, endpoint, mesh_ip, mesh_cidr }?,
      peers: [ { hostname, wg_public_key, mesh_ip, endpoints[],
                 listen_port, last_seen }, ... ] }

GET  /healthz             （无需鉴权）
```

---

## 仓库结构

```
rust/
  Cargo.toml                            workspace 清单
  crates/
    wgmesh-core/    API 类型 · 请求签名 · keyderive · STUN 客户端
    wgmesh-wglink/  对 `wg` 和 `ip` 的薄封装（管理内核 WG 接口）
    wgmesh-coord/   axum HTTP 服务器 + 中继 hub
    wgmesh-agent/   探测状态机 + reconcile 循环
    wgmesh-tools/   ssh-to-wg, wgmesh-smoketest
nix/
  coordinator.nix   services.wgmesh-coord NixOS 模块
  agent.nix         services.wgmesh        NixOS 模块
flake.nix           rustPlatform.buildRustPackage + nixosModules
examples/           示例 NixOS 配置和 coord.json
```

总计约 2,500 行 Rust + 400 行 Nix。

---

## 测试

```sh
cd rust && cargo test --workspace
```

| 测试集                  | 用例数 | 测试什么                                     |
|-------------------------|--------|----------------------------------------------|
| `wgmesh-core`           | 13     | API 序列化、sig 签名/验证、keyderive 不变量    |
| `wgmesh-core` (parity)  | 1      | 推导出的私钥经 `wg pubkey` 算出的公钥与本实现一致 |
| `wgmesh-wglink`         | 4      | syncconf 配置渲染、`wg show dump` 解析        |
| `wgmesh-coord` (单元)   | 11     | 配置默认值、Store 的 IP 分配/持久化           |
| `wgmesh-coord` (集成)   | 5      | register、/peers、未授权拒绝、healthz         |
| `wgmesh-agent`          | 9      | 探测状态机所有跳转、LAN 端点过滤              |
| **总计**                | **43** |                                              |

`keyderive_wg_parity` 测试把推导的私钥喂给 `wg pubkey`，断言结果等于本实现
推导出的公钥——把内核 WireGuard 工具本身当作权威。`wg`/`ssh-keygen`
不在 PATH 上时自动跳过。

---

## 从源码构建

```sh
# Cargo
cd rust
cargo build --release          # → target/release/{wgmesh-coord,wgmesh-agent,ssh-to-wg,wgmesh-smoketest}

# Nix flake
nix build .#wgmesh             # → result/bin/...
nix develop                    # cargo + rustc + clippy + wireguard-tools + coturn
```

flake 的 `postInstall` 会断言每个预期的二进制都进了 `$out/bin/`，
所以构建成功就意味着产物完整。

---

## 安全模型

- Agent 读 `/etc/ssh/ssh_host_ed25519_key`，以 root + `CAP_NET_ADMIN`
  运行。WireGuard 私钥只活在进程内存和内核 WG 设备里——除了一次
  0600 临时文件传给 `wg set private-key`（用完立刻 unlink）外，wgmesh
  本身从不把私钥落盘。
- 协调器只认允许列表；没有自助接入流程也没有带外签发。加节点就是追加
  `ssh-ed25519 …` 一行 + SIGHUP。
- 协调器看得到中继流量的元数据（哪一对节点在传、传了多少）。WG 加密保证它
  读不到载荷。直连的节点对完全绕开协调器。
- 重放攻击被 ±60s 时间戳窗口限定。`/register` 幂等，`/peers` 只读。
  协调器不存 nonce。

---

## 取舍 / 不做的事

- **单协调器。** 协调器掉线不会断已建立的 WG 隧道（内核 WG 不依赖它）；
  只是新节点接入和 endpoint 刷新会暂停。VPS 挂了，从 `state.json`
  备份还原即可——mesh IP 会原样回来。
- **没有 ACL。** 整张网是扁平 `/16`，每个节点都能跟所有其他节点通。
  要分段就在上面叠防火墙。
- **没有 Web UI。** 配置是文件，观察是日志和 `wg show`。
- **只有 IPv4 mesh**（覆盖网；下层 WireGuard 走 IPv6 端点没问题）。
- **不是 Tailscale 替代品。** 没有 MagicDNS、没有 SSH-via-tailscale、
  没有 app connector。就是一张 mesh。
- **HTTP + JSON，不是 gRPC。** Coord 和 agent 在同一个 Rust workspace，
  直接共享 `wgmesh-core::api` 的类型定义——根本不存在跨语言类型漂移问题
  等 protobuf 来解决。Agent 每 30 秒 poll 一次，没有流式或多路复用的需要。
  让协议能用 `curl` 调试、agent 二进制控制在 3 MB 以内，比 gRPC 的
  "现代"气息值钱（换成 tonic 栈，agent 会涨到 5 MB+，构建闭包还得拖
  `protoc` 进来）。

---

## 路线图

- 协调式 UDP 打洞，应对对称 NAT（目前依赖 PersistentKeepalive + STUN，
  锥形 NAT 没问题但对称 NAT 不行）。
- 协调器的 NixOS 模块加 ACME / Let's Encrypt 集成。
- TURN 兜底，给连协调器 WG 端点都不通的节点用。

---

## 许可

MIT。详见 `LICENSE`。

站在 [WireGuard](https://www.wireguard.com)、
[ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek)、
[axum](https://github.com/tokio-rs/axum) 以及 Nix 社区 WireGuard 内核模块
工作的肩膀上。
