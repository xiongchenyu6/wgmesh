# relay sits on both LANs. a and c share LAN 1 and must connect directly;
# b is alone on LAN 2, so a reaches b only through the relay.
{ pkgs, module }:
let
  keys = {
    relay = {
      private = "oBcQaw+w5dh+dnO3wcOb73BbHd5IZIx+3jhMNa7CBn4=";
      public = "pAZPlPlZn0thGSAi481PDZ5mnXsNh6Wxaq4XW1tpaB4=";
    };
    a = {
      private = "wB+uNtXiFKrouwEnYI5MzvrdRuwNBVOO3CU71Mwrk1U=";
      public = "edbMSkhuGaWGw2nSttU0JsP5WCVvnt8KssFhRF/omWY=";
    };
    b = {
      private = "MJ1FFEhjXKtozjWawiASGcKD2P4TLPhjlRNqV18Hj1g=";
      public = "GbG8/7YyQPxgKMTPioSp0DpBy4DKl6WS4Yh6ZP0iT0c=";
    };
    c = {
      private = "2OnSfg19R3tp9PzlB8ZPH6c7P27YfbR//TEYdz7R0Uc=";
      public = "519OvNKMiGbHiibgBXAvjYzscy22IGtgtxq/PsFqX28=";
    };
  };
  meshAddress = {
    relay = "10.42.0.1";
    a = "10.42.0.2";
    b = "10.42.0.3";
    c = "10.42.0.4";
  };
  # Fixed LAN addresses: relay is .1 on both LANs, each node uses its mesh suffix.
  lan = {
    relay = [
      "192.168.1.1"
      "192.168.2.1"
    ];
    a = [ "192.168.1.2" ];
    b = [ "192.168.2.3" ];
    c = [ "192.168.1.4" ];
  };
  node =
    name: vlans:
    { lib, ... }:
    {
      imports = [ module ];
      virtualisation.vlans = vlans;
      networking.interfaces = lib.listToAttrs (
        lib.imap1 (i: ip: {
          name = "eth${toString i}";
          value.ipv4.addresses = lib.mkForce [
            {
              address = ip;
              prefixLength = 24;
            }
          ];
        }) lan.${name}
      );
      environment.etc."wgmesh/private".text = keys.${name}.private;
      environment.etc."wgmesh/gossip".text = "test-gossip-secret";
      services.wgmesh = {
        enable = true;
        cidr = "10.42.0.0/24";
        relay = "relay";
        relayPrefixes = [ "192.0.2.0/24" ];
        gossipPort = 1667;
        privateKeyFile = "/etc/wgmesh/private";
        gossipSecretFile = "/etc/wgmesh/gossip";
        nodes = builtins.mapAttrs (n: k: {
          address = meshAddress.${n};
          publicKey = k.public;
          # b only shares LAN 2 with the relay.
          endpoint =
            if n != "relay" then
              null
            else if name == "b" then
              "192.168.2.1:51820"
            else
              "192.168.1.1:51820";
        }) keys;
      };
    };
in
pkgs.testers.runNixOSTest {
  name = "wgmesh";
  nodes = {
    # 192.0.2.1 stands for a network the relay is a gateway to.
    relay = {
      imports = [
        (node "relay" [
          1
          2
        ])
      ];
      networking.interfaces.lo.ipv4.addresses = [
        {
          address = "192.0.2.1";
          prefixLength = 32;
        }
      ];
    };
    a = node "a" [ 1 ];
    b = node "b" [ 2 ];
    # c builds its interface through networkd, the others through scripts.
    c = {
      imports = [ (node "c" [ 1 ]) ];
      networking.useNetworkd = true;
    };
  };
  testScript = ''
    start_all()
    for m in [relay, a, b, c]:
        m.wait_for_unit("wgautomesh.service")

    with subtest("a and c on the same LAN connect directly"):
        # Each side restores the /32 on its own 30 s loop, so wait for both.
        for m, peer, addr in [(a, "${keys.c.public}", "10.42.0.4"), (c, "${keys.a.public}", "10.42.0.2")]:
            m.wait_until_succeeds(f"wg show wgmesh allowed-ips | grep -q '{peer}.*{addr}/32'", timeout=240)
        a.succeed("ping -c3 -W2 10.42.0.4")
        a.succeed("wg show wgmesh endpoints | grep '${keys.c.public}' | grep -q 192.168.1.")

    with subtest("a reaches b on another LAN through the relay"):
        a.wait_until_succeeds("ping -c1 -W2 10.42.0.3", timeout=120)
        b.succeed("ping -c3 -W2 10.42.0.2")
        a.succeed("wg show wgmesh allowed-ips | grep '${keys.b.public}' | grep -q '(none)'")

    with subtest("relayPrefixes are routed through the relay"):
        a.succeed("ip route get 192.0.2.1 | grep -q 'dev wgmesh'")
        a.succeed("ping -c3 -W2 192.0.2.1")

    with subtest("relay keeps a /32 for every node"):
        for addr in ["10.42.0.2", "10.42.0.3", "10.42.0.4"]:
            relay.succeed(f"wg show wgmesh allowed-ips | grep -q '{addr}/32'")

    with subtest("a dead direct path falls back to the relay"):
        # c goes deaf to a. a keeps dialing the same (only) endpoint, so it
        # must still drop the /32 once the handshake is older than wgautomesh's
        # 300 s TIMEOUT, or a keeps sending into the void.
        c.succeed("iptables -I INPUT -s 192.168.1.2 -p udp --dport 51820 -j DROP")
        for m, peer in [(a, "${keys.c.public}"), (c, "${keys.a.public}")]:
            m.wait_until_succeeds(f"wg show wgmesh allowed-ips | grep '{peer}' | grep -q '(none)'", timeout=600)
        a.succeed("ping -c3 -W2 10.42.0.4")
        c.succeed("iptables -D INPUT -s 192.168.1.2 -p udp --dport 51820 -j DROP")
  '';
}
