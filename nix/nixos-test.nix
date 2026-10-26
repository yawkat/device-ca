# Boots a VM running the NixOS module and exercises enrollment, renewal, the CA download and public certificates.
{
  self,
  testers,
  pebble,
  fetchFromGitHub,
  writeText,
  writers,
}:

let
  # nixpkgs' pebble predates certificate profiles
  pebble' = pebble.overrideAttrs (
    finalAttrs: _: {
      version = "2.10.1";
      src = fetchFromGitHub {
        owner = "letsencrypt";
        repo = "pebble";
        rev = "v${finalAttrs.version}";
        hash = "sha256-O9lVC/GhbN3R7RuWZzr1kznbz0ffr+qdNSa/FpVTWzY=";
      };
    }
  );

  # with pebble's test certificate, which acme4j's acme://pebble provider trusts
  pebbleConfig = writeText "pebble-config.json" (
    builtins.toJSON {
      pebble = {
        listenAddress = "127.0.0.1:14000";
        managementListenAddress = "127.0.0.1:15000";
        certificate = "${pebble'.src}/test/certs/localhost/cert.pem";
        privateKey = "${pebble'.src}/test/certs/localhost/key.pem";
        httpPort = 5002;
        tlsPort = 5001;
        profiles = {
          default.validityPeriod = 7776000;
          shortlived.validityPeriod = 576000;
        };
      };
    }
  );

  # Stands in for the Cloudflare API: keeps the TXT records of cats.coffee in pebble-challtestsrv, which serves them
  # as that zone's name server and is pebble's resolver.
  cloudflareStub = writers.writePython3 "cloudflare-stub" { flakeIgnore = [ "E501" ]; } ''
    import json
    import urllib.request
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import urlparse, parse_qs

    records = {}
    next_id = 0


    def challtestsrv(path, body):
        request = urllib.request.Request(
            "http://127.0.0.1:8055" + path, data=json.dumps(body).encode())
        urllib.request.urlopen(request).read()


    class Handler(BaseHTTPRequestHandler):
        def reply(self, result):
            body = json.dumps({"success": True, "errors": [], "result": result})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode())

        def check(self):
            auth = self.headers["Authorization"]
            assert auth == "Bearer test-token", auth
            return urlparse(self.path)

        def do_GET(self):
            url = self.check()
            query = parse_qs(url.query)
            if url.path == "/zones":
                assert query["name"] == ["cats.coffee"], query
                self.reply([{"id": "zone", "name_servers": ["127.0.0.1:8053"]}])
            elif url.path == "/zones/zone/dns_records":
                name = query["name"][0]
                self.reply([{"id": i} for i, r in records.items() if r[0] == name])
            else:
                raise Exception(url.path)

        def do_POST(self):
            global next_id
            assert self.check().path == "/zones/zone/dns_records"
            length = int(self.headers["Content-Length"])
            body = json.loads(self.rfile.read(length))
            assert body["type"] == "TXT", body
            next_id += 1
            records[str(next_id)] = (body["name"], body["content"])
            challtestsrv("/set-txt", {"host": body["name"], "value": body["content"]})
            self.reply({"id": str(next_id)})

        def do_DELETE(self):
            name, _ = records.pop(self.check().path.split("/")[-1])
            challtestsrv("/clear-txt", {"host": name})
            for other_name, value in records.values():
                if other_name == name:
                    challtestsrv("/set-txt", {"host": name, "value": value})
            self.reply({})


    HTTPServer(("127.0.0.1", 8555), Handler).serve_forever()
  '';
in
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
        cloudflareTokenCredential = "device-ca-cloudflare-token";
      };
      environment.etc."credstore/device-ca-cloudflare-token".text = "test-token";
      systemd.services.device-ca.environment = {
        ACME_DIRECTORY = "acme://pebble/localhost:14000";
        CLOUDFLARE_API_URL = "http://127.0.0.1:8555";
      };

      systemd.services.pebble-challtestsrv = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pebble'}/bin/pebble-challtestsrv -management 127.0.0.1:8055 -dnsserver 127.0.0.1:8053 -defaultIPv4 127.0.0.1 -defaultIPv6 '' -http01 '' -https01 '' -doh '' -tlsalpn01 ''";
      };
      systemd.services.pebble = {
        wantedBy = [ "multi-user.target" ];
        environment = {
          PEBBLE_VA_NOSLEEP = "1";
          PEBBLE_WFE_NONCEREJECT = "0";
        };
        serviceConfig.ExecStart = "${pebble'}/bin/pebble -config ${pebbleConfig} -dnsserver 127.0.0.1:8053";
      };
      systemd.services.cloudflare-stub = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = cloudflareStub;
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
      networking.hosts."127.0.0.1" = [
        "test.local.yawk.at"
        "other.local.yawk.at"
        "third.local.yawk.at"
      ];
      environment.systemPackages = [
        pkgs.curl
        pkgs.openssl
        pkgs.dig
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

    # a public certificate, authenticated by the current certificate, by a DNS-01 challenge through the
    # _acme-challenge CNAME into cats.coffee
    machine.wait_for_open_port(14000)
    machine.wait_for_open_port(8055)
    machine.wait_for_open_port(8555)
    machine.succeed("curl -sf -d '{\"host\": \"_acme-challenge.test.local.yawk.at\", \"target\": \"test._acme.cats.coffee\"}' http://127.0.0.1:8055/set-cname")
    renewed = machine.succeed("cat /tmp/renewed.pem")
    der = ",".join(re.sub(r"\s", "", b) for b in re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", renewed, re.S))
    machine.succeed("cd /tmp && openssl req -subj /CN=test.local.yawk.at -addext subjectAltName=DNS:test.local.yawk.at -newkey rsa:2048 -nodes -keyout public-key.pem -out public-csr.pem")
    machine.succeed(f"cd /tmp && curl -sf -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Forwarded-TLS-Client-Cert: {der}' -H 'Content-Type: application/x-pem-file' --data-binary @public-csr.pem {url}/csr/public > public.pem")
    machine.succeed("openssl x509 -in /tmp/public.pem -noout -ext subjectAltName | grep DNS:test.local.yawk.at")
    # the shortlived profile
    machine.succeed("openssl x509 -in /tmp/public.pem -noout -checkend 518400")
    machine.fail("openssl x509 -in /tmp/public.pem -noout -checkend 864000")
    machine.succeed("cmp <(openssl x509 -in /tmp/public.pem -noout -pubkey) <(openssl pkey -in /tmp/public-key.pem -pubout)")
    # the challenge record is gone again
    machine.succeed("test -z \"$(dig +short @127.0.0.1 -p 8053 TXT test._acme.cats.coffee)\"")
    machine.succeed("ls /var/lib/device-ca/acme/issued/test.local.yawk.at | wc -l | grep -x 1")
    machine.succeed("test \"$(stat -c '%a' /var/lib/device-ca/acme/account.key)\" = '600'")
    machine.succeed("journalctl -u device-ca.service | grep 'Using ACME account https://localhost:14000/'")
    # only for names whose CNAME points into cats.coffee
    machine.succeed("cd /tmp && openssl req -subj /CN=other.local.yawk.at -newkey rsa:2048 -nodes -keyout key.pem -out csr.pem")
    machine.succeed(f"cd /tmp && curl -sf -H 'X-Forwarded-For: 127.0.0.1' -H 'Content-Type: application/x-pem-file' --data-binary @csr.pem {url}/csr/enroll > other.pem")
    other = machine.succeed("cat /tmp/other.pem")
    der = ",".join(re.sub(r"\s", "", b) for b in re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", other, re.S))
    machine.succeed("cd /tmp && openssl req -subj /CN=other.local.yawk.at -addext subjectAltName=DNS:other.local.yawk.at -newkey rsa:2048 -nodes -keyout public-key.pem -out public-csr.pem")
    status = machine.succeed(f"cd /tmp && curl -s -o error.txt -w '%{{http_code}}' -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Forwarded-TLS-Client-Cert: {der}' -H 'Content-Type: application/x-pem-file' --data-binary @public-csr.pem {url}/csr/public")
    assert status == "502", status
    machine.succeed("grep 'Challenge for other.local.yawk.at failed' /tmp/error.txt")

    # the ACME account (key) survives a restart
    machine.succeed("systemctl restart device-ca.service")
    machine.wait_for_open_port(8081)
    machine.succeed("curl -sf -d '{\"host\": \"_acme-challenge.third.local.yawk.at\", \"target\": \"third._acme.cats.coffee\"}' http://127.0.0.1:8055/set-cname")
    machine.succeed("cd /tmp && openssl req -subj /CN=third.local.yawk.at -newkey rsa:2048 -nodes -keyout key.pem -out csr.pem")
    machine.succeed(f"cd /tmp && curl -sf -H 'X-Forwarded-For: 127.0.0.1' -H 'Content-Type: application/x-pem-file' --data-binary @csr.pem {url}/csr/enroll > third.pem")
    third = machine.succeed("cat /tmp/third.pem")
    der = ",".join(re.sub(r"\s", "", b) for b in re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", third, re.S))
    machine.succeed("cd /tmp && openssl req -subj /CN=third.local.yawk.at -addext subjectAltName=DNS:third.local.yawk.at -newkey rsa:2048 -nodes -keyout public-key.pem -out public-csr.pem")
    machine.succeed(f"cd /tmp && curl -sf -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Forwarded-TLS-Client-Cert: {der}' -H 'Content-Type: application/x-pem-file' --data-binary @public-csr.pem {url}/csr/public > public.pem")
    machine.succeed("openssl x509 -in /tmp/public.pem -noout -ext subjectAltName | grep DNS:third.local.yawk.at")
    machine.succeed("journalctl -u device-ca.service | grep -c 'Created ACME account key' | grep -x 1")
    machine.succeed("journalctl -u device-ca.service | grep 'Using ACME account' | awk '{print $NF}' | sort -u | wc -l | grep -x 1")

    # without the token credential, the CA still runs and only public certificates are unavailable
    machine.succeed("rm /etc/credstore/device-ca-cloudflare-token && systemctl restart device-ca.service")
    machine.wait_for_open_port(8081)
    status = machine.succeed(f"cd /tmp && curl -s -o error.txt -w '%{{http_code}}' -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Forwarded-TLS-Client-Cert: {der}' -H 'Content-Type: application/x-pem-file' --data-binary @public-csr.pem {url}/csr/public")
    assert status == "503", status
    machine.succeed("cd /tmp && curl -sfO {url}/ca.tar".replace("{url}", url))

    # a new TLS certificate restarts its users
    machine.succeed("systemctl show -P InvocationID tls-consumer.service > /tmp/inv")
    machine.succeed("systemctl stop device-ca.service && rm /var/lib/device-ca-tls/local.pem && systemctl start device-ca.service")
    machine.wait_until_succeeds("test \"$(systemctl show -P InvocationID tls-consumer.service)\" != \"$(cat /tmp/inv)\"")

    # a normal stop is not a failure
    machine.succeed("systemctl stop device-ca.service")
    machine.fail("systemctl is-failed device-ca.service")
  '';
}
