# device-ca

Certificate infrastructure for my internal network. Currently not configurable for other
networks.

TOFU-based authentication.

## Nix

`nix build .#server` builds the server, `.#cert-request` the client. `nixosModules.default` provides
`services.device-ca`; see `nix/module.nix` for the options and `nix/nixos-test.nix` for an example.
After changing Gradle dependencies, regenerate `nix/deps.json` with
`nix build .#server.mitmCache.updateScript && ./result`.
