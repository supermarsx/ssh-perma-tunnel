# frozen_string_literal: true

# Homebrew formula for `spt` (ssh-perma-tunnel).
#
# Placeholders substituted by `scripts/release/update-packaging.sh` after a
# tagged release:
#   <VERSION>             — release version, e.g. 0.1.0 (no leading "v").
#   <SHA256_MACOS_ARM64>  — sha256 of spt-<VERSION>-aarch64-apple-darwin.tar.gz
#   <SHA256_MACOS_AMD64>  — sha256 of spt-<VERSION>-x86_64-apple-darwin.tar.gz
#   <SHA256_LINUX_ARM64>  — sha256 of spt-<VERSION>-aarch64-unknown-linux-gnu.tar.gz
#   <SHA256_LINUX_AMD64>  — sha256 of spt-<VERSION>-x86_64-unknown-linux-gnu.tar.gz
#
# See packaging/README.md for the full release/maintenance flow.
class Spt < Formula
  desc "Permanent SSH/SSH3 tunnels — local/remote port forwards that survive drops"
  homepage "https://github.com/Mariana/ssh-perma-tunnel"
  version "<VERSION>"
  license "MIT"

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
    bin.install "spt"

    # Install pre-generated man pages if shipped in the tarball.
    if Dir.exist?("share/man/man1")
      man1.install Dir["share/man/man1/spt*.1"]
    end

    # Shell completions, generated at install time from the binary itself.
    generate_completions_from_executable(bin/"spt", "completion", "generate")
  end

  test do
    assert_match(/spt #{version}/, shell_output("#{bin}/spt --version"))
  end
end
