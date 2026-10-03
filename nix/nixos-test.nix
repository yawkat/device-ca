# Boots a VM running the NixOS module and exercises enrollment, renewal and the CA download.
{
  self,
  testers,
}:

testers.runNixOSTest {
  name = "device-ca";

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ self.nixosModules.default ];
      services.device-ca = {
        enable = true;
        port = 8081;
        reloadServices = [ "tls-consumer.service" ];
      };
      # stands in for the reverse proxy: reads the TLS key through the group, and is restarted when it changes
      users.users.tls-consumer = {
        isSystemUser = true;
        group = "tls-consumer";
        extraGroups = [ "device-ca" ];
      };
      users.groups.tls-consumer = { };
      systemd.services.tls-consumer = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          User = "tls-consumer";
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${pkgs.coreutils}/bin/true";
        };
      };
      # the server checks that the CN resolves to the requesting address
      networking.hosts."127.0.0.1" = [ "test.local.yawk.at" ];
      environment.systemPackages = [
        pkgs.curl
        pkgs.openssl
      ];
      virtualisation.memorySize = 1024;
    };

  testScript = ''
    import re

    url = "http://127.0.0.1:8081"

    machine.wait_for_unit("device-ca.service")
    machine.wait_for_open_port(8081)

    # only reachable through the reverse proxy
    machine.fail("ss -ltnH | grep ':8081' | grep -v '127.0.0.1'")

    # the CA certificates, in a tar
    machine.succeed(f"cd /tmp && curl -sfO {url}/ca.tar && tar xf ca.tar && test -s 0.pem")

    # the reverse proxy's certificate, signed by the current CA
    machine.wait_for_file("/var/lib/device-ca-tls/local.key")
    machine.succeed("openssl verify -CAfile /tmp/0.pem /var/lib/device-ca-tls/local.pem")
    machine.succeed("openssl x509 -in /var/lib/device-ca-tls/local.pem -noout -subject | grep ca.local.yawk.at")
    machine.succeed("test \"$(stat -c '%U %G %a' /var/lib/device-ca-tls/local.key)\" = 'device-ca device-ca 640'")
    machine.succeed("test \"$(stat -c '%a' /var/lib/device-ca)\" = '700'")
    machine.succeed("test \"$(stat -c '%a' /var/lib/device-ca/current.key)\" = '700'")
    machine.succeed("runuser -u tls-consumer -- cat /var/lib/device-ca-tls/local.key")
    machine.fail("runuser -u tls-consumer -- ls /var/lib/device-ca")

    # enrollment, authenticated by the requesting address
    machine.succeed("cd /tmp && openssl req -subj /CN=test.local.yawk.at -newkey rsa:2048 -nodes -keyout key.pem -out csr.pem")
    machine.succeed(f"cd /tmp && curl -sf -H 'X-Forwarded-For: 127.0.0.1' -H 'Content-Type: application/x-pem-file' --data-binary @csr.pem {url}/csr/enroll > chain.pem")
    machine.succeed("cd /tmp && openssl verify -CAfile 0.pem chain.pem")
    machine.fail(f"cd /tmp && curl -sf -H 'X-Forwarded-For: 127.0.0.2' -H 'Content-Type: application/x-pem-file' --data-binary @csr.pem {url}/csr/enroll")

    # renewal, authenticated by the previous certificate in traefik's X-Forwarded-TLS-Client-Cert format
    chain = machine.succeed("cat /tmp/chain.pem")
    der = ",".join(re.sub(r"\s", "", b) for b in re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", chain, re.S))
    machine.succeed(f"cd /tmp && curl -sf -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Forwarded-TLS-Client-Cert: {der}' -H 'Content-Type: application/x-pem-file' --data-binary @csr.pem {url}/csr/renew > renewed.pem")
    machine.succeed("cd /tmp && openssl verify -CAfile 0.pem renewed.pem")
    machine.succeed("ls /var/lib/device-ca/leafCerts/test.local.yawk.at | wc -l | grep -x 2")

    # a new TLS certificate restarts its users
    machine.succeed("systemctl show -P InvocationID tls-consumer.service > /tmp/inv")
    machine.succeed("systemctl stop device-ca.service && rm /var/lib/device-ca-tls/local.pem && systemctl start device-ca.service")
    machine.wait_until_succeeds("test \"$(systemctl show -P InvocationID tls-consumer.service)\" != \"$(cat /tmp/inv)\"")

    # a normal stop is not a failure
    machine.succeed("systemctl stop device-ca.service")
    machine.fail("systemctl is-failed device-ca.service")
  '';
}
