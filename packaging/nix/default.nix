# Nix package definition for spt.
#
# Build (from repo root):
#   nix-build packaging/nix
#
# Or as part of a flake / overlay:
#   pkgs.callPackage ./packaging/nix { }
#
# Placeholders substituted by `scripts/release/update-packaging.sh`:
#   <VERSION>     — release version, e.g. 0.1.0
#   <NIX_HASH>    — sri hash of the GitHub source tarball
#                   (use `nix-prefetch-github Mariana ssh-perma-tunnel --rev v<VERSION>`)
{ lib
, rustPlatform
, fetchFromGitHub
, openssl
, pkg-config
, installShellFiles
, stdenv
, darwin
}:

rustPlatform.buildRustPackage rec {
  pname = "spt";
  version = "<VERSION>";

  src = fetchFromGitHub {
    owner = "Mariana";
    repo = "ssh-perma-tunnel";
    rev = "v${version}";
    hash = "<NIX_HASH>";
  };

  # Use the Cargo.lock vendored in the repository to keep the build hermetic.
  cargoLock = {
    lockFile = ../../Cargo.lock;
  };

  cargoBuildFlags = [ "--bin" "spt" ];
  cargoTestFlags = [ "--bin" "spt" ];

  nativeBuildInputs = [
    pkg-config
    installShellFiles
  ];

  buildInputs = [
    openssl
  ] ++ lib.optionals stdenv.isDarwin [
    darwin.apple_sdk.frameworks.Security
    darwin.apple_sdk.frameworks.SystemConfiguration
  ];

  # Some integration tests need real network/keychain access; skip those.
  checkFlags = [
    "--skip=integration"
    "--skip=keychain"
  ];

  postInstall = ''
    # Man pages.
    if [ -d "$src/packaging/man" ]; then
      for page in $src/packaging/man/spt*.1; do
        [ -f "$page" ] || continue
        installManPage "$page"
      done
    fi

    # Shell completions, generated from the freshly built binary.
    installShellCompletion --cmd spt \
      --bash <($out/bin/spt completion generate bash) \
      --zsh  <($out/bin/spt completion generate zsh)  \
      --fish <($out/bin/spt completion generate fish)

    mkdir -p "$out/share/powershell/Modules/spt" "$out/share/elvish/lib"
    "$out/bin/spt" completion generate powershell > "$out/share/powershell/Modules/spt/spt.psm1"
    "$out/bin/spt" completion generate elvish > "$out/share/elvish/lib/spt.elv"
  '';

  meta = with lib; {
    description = "Permanent SSH/SSH3 tunnels — local/remote port forwards that survive drops";
    homepage = "https://github.com/Mariana/ssh-perma-tunnel";
    changelog = "https://github.com/Mariana/ssh-perma-tunnel/blob/v${version}/changelog.md";
    license = licenses.mit;
    maintainers = with maintainers; [ ];
    mainProgram = "spt";
    platforms = platforms.unix;
  };
}
