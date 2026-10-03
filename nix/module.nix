{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.device-ca;
in
{
  options.services.device-ca = {
    enable = lib.mkEnableOption "the device-ca certificate authority";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.server;
      defaultText = lib.literalExpression "device-ca.packages.\${system}.server";
      description = "The device-ca package to use.";
    };

    host = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = ''
        Address the HTTP server binds to. The server trusts the `X-Forwarded-For` and
        `X-Forwarded-TLS-Client-Cert` headers for authentication, so it must only be reachable through a reverse proxy
        that sets them (traefik with the `passTLSClientCert` middleware).
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8080;
      description = "TCP port the HTTP server listens on.";
    };

    dataDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/device-ca";
      description = ''
        Directory holding the CA keys, the CA certificates and the issued leaf certificates. Must be below
        `/var/lib`, it is managed through systemd's `StateDirectory`.
      '';
    };

    tlsDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/device-ca-tls";
      description = ''
        Directory where the server maintains the reverse proxy's certificate for ca.local.yawk.at (`local.pem`, the
        certificate followed by the signing CA certificate, and `local.key`). It is readable by
        {option}`services.device-ca.group`, so add the reverse proxy's user to that group.
      '';
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "device-ca";
      description = "User the server runs as. Created automatically if left at the default.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "device-ca";
      description = "Group the server runs as. Created automatically if left at the default.";
    };

    reloadServices = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "traefik.service" ];
      description = "Units to restart when the server replaces the certificate in {option}`services.device-ca.tlsDir`.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        # both are interpolated unquoted into the unit and tmpfiles
        assertion = lib.all (d: builtins.match "/[^[:space:]%]*" d != null) [
          cfg.dataDir
          cfg.tlsDir
        ];
        message = "services.device-ca.dataDir and tlsDir must be absolute paths without whitespace or '%'.";
      }
      {
        assertion = lib.hasPrefix "/var/lib/" cfg.dataDir;
        message = "services.device-ca.dataDir must be below /var/lib.";
      }
    ];

    users.users = lib.mkIf (cfg.user == "device-ca") {
      device-ca = {
        isSystemUser = true;
        inherit (cfg) group;
        home = cfg.dataDir;
      };
    };

    users.groups = lib.mkIf (cfg.group == "device-ca") { device-ca = { }; };

    systemd.services.device-ca = {
      description = "device-ca certificate authority";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      environment = {
        STORAGE = cfg.dataDir;
        LOCAL_KEY_PATH = "${cfg.tlsDir}/local.key";
        LOCAL_CERT_PATH = "${cfg.tlsDir}/local.pem";
        MICRONAUT_SERVER_HOST = cfg.host;
        MICRONAUT_SERVER_PORT = toString cfg.port;
      };

      serviceConfig = {
        Type = "simple";
        ExecStart = lib.getExe cfg.package;
        User = cfg.user;
        Group = cfg.group;
        Restart = "on-failure";
        # the JVM exits with 128+SIGTERM on a normal stop
        SuccessExitStatus = "143";

        StateDirectory = lib.removePrefix "/var/lib/" cfg.dataDir;
        StateDirectoryMode = "0700";
        ReadWritePaths = [ cfg.tlsDir ];
        # the reverse proxy reads the TLS key through the group
        UMask = "0027";

        # hardening: the server only needs to listen on a port, resolve names and write its state
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
        CapabilityBoundingSet = if cfg.port < 1024 then [ "CAP_NET_BIND_SERVICE" ] else "";
        AmbientCapabilities = lib.optional (cfg.port < 1024) "CAP_NET_BIND_SERVICE";
      };
    };

    systemd.tmpfiles.rules = [ "d ${cfg.tlsDir} 0750 ${cfg.user} ${cfg.group} -" ];

    # The server writes local.pem first and local.key last, so the key's close-after-write marks a complete pair
    systemd.paths.device-ca-tls = lib.mkIf (cfg.reloadServices != [ ]) {
      wantedBy = [ "multi-user.target" ];
      pathConfig.PathChanged = "${cfg.tlsDir}/local.key";
    };
    systemd.services.device-ca-tls = lib.mkIf (cfg.reloadServices != [ ]) {
      description = "Restart the users of the device-ca TLS certificate";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${config.systemd.package}/bin/systemctl try-restart ${lib.escapeShellArgs cfg.reloadServices}";
      };
    };
  };
}
