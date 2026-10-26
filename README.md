# device-ca

Certificate infrastructure for my internal network. Currently not configurable for other
networks.

TOFU-based authentication.

## Nix

`nix build .#server` builds the server, `.#cert-request` the client. `nixosModules.default` provides
`services.device-ca`; see `nix/module.nix` for the options and `nix/nixos-test.nix` for an example.
After changing Gradle dependencies, regenerate `nix/deps.json` with
`nix build .#server.mitmCache.updateScript && ./result`.

## Public certificates

Hosts can also get a publicly trusted Let's Encrypt certificate for their name, for devices that don't trust the local
CA (`cert-request renew-public`, `POST /csr/public`). The host authenticates with its current local certificate for
the same name; device-ca holds the ACME account and gets the certificate by a DNS-01 challenge (`shortlived` profile,
about 6 days), so hosts never hold DNS credentials. The private key stays on the host.

device-ca can only write TXT records in the `cats.coffee` zone (`services.device-ca.cloudflareTokenCredential`, a Cloudflare
token with Zone:Read and DNS:Edit on that zone only). A name can only get a certificate if its challenge record is
delegated there:

    _acme-challenge.paperless.local.yawk.at CNAME paperless._acme.cats.coffee

A CAA record on `local.yawk.at` should restrict issuance to device-ca's ACME account (logged at the first request):

    local.yawk.at CAA 0 issue "letsencrypt.org; accounturi=<account>; validationmethods=dns-01"
    local.yawk.at CAA 0 issuewild ";"
