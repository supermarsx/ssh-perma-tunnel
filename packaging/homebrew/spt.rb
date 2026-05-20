# frozen_string_literal: true

# Homebrew formula for `spt` (ssh-perma-tunnel).
#
# Placeholders substituted by `scripts/release/bump-homebrew.sh` after a
# tagged release:
#   <VERSION>             - release version, e.g. 0.1.0 (no leading "v").
#   <SHA256_MACOS_ARM64>  - sha256 of spt-<VERSION>-aarch64-apple-darwin.tar.gz
#   <SHA256_MACOS_AMD64>  - sha256 of spt-<VERSION>-x86_64-apple-darwin.tar.gz
#   <SHA256_LINUX_ARM64>  - sha256 of spt-<VERSION>-aarch64-unknown-linux-gnu.tar.gz
#   <SHA256_LINUX_AMD64>  - sha256 of spt-<VERSION>-x86_64-unknown-linux-gnu.tar.gz
#
# See packaging/homebrew/README.md for the full release/submission flow.
class Spt < Formula
  desc "Permanent SSH/SSH3 tunnels - local/remote port forwards that survive drops"
  homepage "https://github.com/Mariana/ssh-perma-tunnel"
  version "<VERSION>"
  license "MIT"

  livecheck do
    url :stable
    strategy :github_latest
  end

  head do
    url "https://github.com/Mariana/ssh-perma-tunnel.git", branch: "main"
    depends_on "rust" => :build
  end

  on_macos do
    on_arm do
      url "https://github.com/Mariana/ssh-perma-tunnel/releases/download/v#{version}/spt-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "<SHA256_MACOS_ARM64>"
    end
    on_intel do
      url "https://github.com/Mariana/ssh-perma-tunnel/releases/download/v#{version}/spt-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "<SHA256_MACOS_AMD64>"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/Mariana/ssh-perma-tunnel/releases/download/v#{version}/spt-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "<SHA256_LINUX_ARM64>"
    end
    on_intel do
      url "https://github.com/Mariana/ssh-perma-tunnel/releases/download/v#{version}/spt-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "<SHA256_LINUX_AMD64>"
    end
  end

  def install
    if build.head?
      # Source build (HEAD): cargo-install the workspace's binary crate.
      system "cargo", "install", *std_cargo_args(path: "crates/spt-bin")
    else
      # Pre-built release tarball ships the binary at the archive root and
      # bundles man pages under share/man/man1/. The shell-completion path
      # below regenerates completions at install time from the binary.
      bin.install "spt"
      man1.install Dir["share/man/man1/spt*.1"] if Dir.exist?("share/man/man1")
    end

    # Generate and install shell completions from the binary.
    generate_completions_from_executable(bin/"spt", "completion", "generate")
    (share/"powershell/Modules/spt").mkpath
    File.write(share/"powershell/Modules/spt/spt.psm1",
      Utils.safe_popen_read(bin/"spt", "completion", "generate", "powershell"))
    (share/"elvish/lib").mkpath
    File.write(share/"elvish/lib/spt.elv",
      Utils.safe_popen_read(bin/"spt", "completion", "generate", "elvish"))
  end

  test do
    # --version must contain the formula's version string.
    assert_match(/spt #{version}/, shell_output("#{bin}/spt --version"))

    # Validate a minimal, self-contained config. Inlined so the test does
    # not depend on examples/ being shipped in the release tarball.
    (testpath/"minimal.toml").write <<~TOML
      # Minimal spt config for `brew test` smoke validation.
      version = 1

      [[profiles]]
      name = "minimal"
      enabled = true
      protocol = "ssh2"
      host = "bastion.example.com"
      port = 22
      user = "alice"

      [profiles.auth]
      method = "agent"

      [profiles.trust]
      mode = "known_hosts"
      strict = true

      [[profiles.forwards]]
      name = "web"
      type = "local"
      transport = "tcp"
      bind = "127.0.0.1:8080"
      target = "service.internal:80"
      target_resolve = "remote"
      required = true
    TOML

    system bin/"spt", "config", "validate", "--config", testpath/"minimal.toml"
  end
end
