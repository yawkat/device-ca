# The client (cert-request.py), used by the local PKI module in nixcfg-shared.
{
  lib,
  python3Packages,
}:

python3Packages.buildPythonApplication {
  pname = "cert-request";
  version = "0-unstable";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = ../cert-request.py;
  };

  format = "other"; # not a standard Python package, just a script

  propagatedBuildInputs = with python3Packages; [
    cryptography
    requests
  ];

  installPhase = ''
    install -Dm755 cert-request.py $out/bin/cert-request
  '';

  meta = {
    description = "Client for the yawk.at local PKI";
    homepage = "https://github.com/yawkat/device-ca";
    mainProgram = "cert-request";
    platforms = lib.platforms.linux;
  };
}
