# Builds the server with Gradle and runs the test suite.
#
# Dependencies are pinned in ./deps.json. After changing any Gradle dependency or plugin, regenerate it by running
# this from the repository root (new files must be `git add`ed first so the flake sees them):
#
#   nix build .#server.mitmCache.updateScript && ./result
{
  lib,
  stdenv,
  gradle_8,
  jdk21,
  jdk21_headless,
  makeWrapper,
  # used by the tests
  openssl,
  curl,
  gnutar,
}:

let
  gradle = gradle_8.override { java = jdk21; };
in
stdenv.mkDerivation (finalAttrs: {
  pname = "device-ca";
  version = "0.1";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../build.gradle.kts
      ../settings.gradle.kts
      ../gradle.properties
      ../src
    ];
  };

  nativeBuildInputs = [
    gradle
    makeWrapper
  ];

  mitmCache = gradle.fetchDeps {
    pkg = finalAttrs.finalPackage;
    data = ./deps.json;
  };

  passthru = { inherit gradle; };

  # the application distribution (lib/*.jar and start scripts)
  gradleBuildTask = "installDist";
  # The default, nixDownloadDeps, resolves every configuration, and Kotlin's *DependenciesMetadata ones fail to
  # resolve here (micronaut-inject without a version). Running the real tasks records what they need instead.
  gradleUpdateTask = "installDist test";

  doCheck = true;
  gradleCheckTask = "test";
  # The tests talk to their server with curl, which would otherwise go through the mitm-cache proxy
  no_proxy = "localhost,127.0.0.1";
  NO_PROXY = "localhost,127.0.0.1";
  nativeCheckInputs = [
    openssl
    curl
    gnutar
  ];

  installPhase = ''
    runHook preInstall
    mkdir -p $out/share/device-ca
    cp -r build/install/device-ca/lib $out/share/device-ca/lib
    # the runtime classpath in Gradle's order, taken from the distribution's start script
    classpath=$(sed -n 's|^CLASSPATH=||p' build/install/device-ca/bin/device-ca \
      | sed "s|\$APP_HOME/lib/|$out/share/device-ca/lib/|g")
    test -n "$classpath"
    makeWrapper ${lib.getExe jdk21_headless} $out/bin/device-ca \
      --add-flags "-cp $classpath at.yawk.deviceca.ApplicationKt"
    runHook postInstall
  '';

  meta = {
    description = "Certificate authority for the local.yawk.at network";
    homepage = "https://github.com/yawkat/device-ca";
    mainProgram = "device-ca";
    platforms = lib.platforms.linux;
    sourceProvenance = with lib.sourceTypes; [
      fromSource
      binaryBytecode # dependencies from the mitm cache
    ];
  };
})
