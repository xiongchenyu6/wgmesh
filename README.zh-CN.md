# wgmesh

[English](./README.md) · **简体中文**

用 NixOS 自带模块拼出来的内核 WireGuard 全互联网络。没有自己的守护进程:
wgmesh 只是一个 NixOS 模块,外加给 [wgautomesh](https://git.deuxfleurs.fr/Deuxfleurs/wgautomesh)
打的一个小补丁。

- `networking.wireguard` 建接口,只配一个静态 peer —— **中继**,它承载整个 mesh 网段。
- `services.wgautomesh` 把其余每个节点加成 `/32` peer,通过加密 gossip 和局域网广播交换
  endpoint,双方同时去拨中继看到的对端地址,完成 NAT 打洞。
- 补丁(`nix/wgautomesh-relay-fallback.patch`,配置项 `relay_fallback`)让节点只在握手新鲜时
  才拿到 `/32`。直连不通的一对节点会一直走中继的覆盖路由,一旦握手成功就切到直连。

节点列表、地址、密钥全部声明在 Nix 里:节点出现在每台主机的 `nodes` 里并重新部署,就加入了。

## 用法

```nix
{
  inputs.wgmesh.url = "github:xiongchenyu6/wgmesh";

  # 在 NixOS 配置里
  imports = [ inputs.wgmesh.nixosModules.default ];

  services.wgmesh = {
    enable = true;
    cidr = "10.42.0.0/24";
    relay = "hub";
    privateKeyFile = "/run/secrets/wireguard";
    gossipSecretFile = "/run/secrets/wgmesh-gossip"; # 所有节点相同
    gossipPort = 1666;
    nodes = {
      hub = { address = "10.42.0.1"; publicKey = "..."; endpoint = "203.0.113.1:51820"; };
      laptop = { address = "10.42.0.20"; publicKey = "..."; };
      desktop = { address = "10.42.0.21"; publicKey = "..."; };
    };
  };
}
```

`hostName` 默认取 `networking.hostName`,用来在 `nodes` 里找到本机。`relayPrefixes`
是 mesh 之外、其余节点经中继访问的网段(中继充当网关的网络)。中继需要公网 endpoint,
并会打开 `net.ipv4.ip_forward`;其余节点只需要能出站 UDP。防火墙会放行 WireGuard 端口
(默认 51820)和 gossip 端口(默认 1666)。Nix 求值时会校验 `cidr` 和所有节点地址,
包括重复地址以及地址不在 mesh 网段内的情况。

在 nix-darwin 上，请改为导入 `inputs.wgmesh.darwinModules.default`。Darwin 节点使用
`wg-quick` 和 `wireguard-go`;中继节点仍必须运行在 NixOS 上。

## 限制

- IPv4 overlay,每个节点一个地址,不做子网路由。
- 支持 NixOS 和 nix-darwin 节点；中继节点必须运行在 NixOS 上。
- 只有一个中继。两端都是对称 NAT 的节点会一直走中继。
- wgautomesh 每 30 秒一轮,握手超时 5 分钟:新直连最多 30 秒两端才稳定;
  对端突然消失时,直连路由最多保留 5 分钟才回落到中继。

## 测试

`nix flake check` 跑一个四台虚拟机的测试(`tests/vm.nix`):同一局域网的两个节点必须直连,
另一局域网的第三个节点必须经中继可达,中继必须给每个节点保留 `/32`。

## License

MIT
