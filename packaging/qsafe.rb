# Homebrew formula for Qsafe.
#
# This is a template for a Homebrew tap. To publish:
#   1. Create a tap repo, e.g. github.com/SP1R4/homebrew-qsafe
#   2. Tag a release (git tag v7.0.0 && git push --tags); the release workflow
#      attaches qsafe-vX-*.tar.gz artifacts.
#   3. Update `url` to the source tarball for the tag and fill in `sha256`
#      (`brew fetch` or `shasum -a 256` on the downloaded tarball).
#   4. Drop this file in the tap's Formula/ directory.
#
# Users then: brew install SP1R4/qsafe/qsafe
class Qsafe < Formula
  desc "Hybrid post-quantum file encryption and signing (X25519 + ML-KEM-1024)"
  homepage "https://github.com/SP1R4/Qsafe"
  url "https://github.com/SP1R4/Qsafe/archive/refs/tags/v7.0.0.tar.gz"
  # Fill in after tagging: shasum -a 256 on the v7.0.0 source tarball.
  sha256 "REPLACE_WITH_v7.0.0_SOURCE_TARBALL_SHA256"
  license "MIT"

  depends_on "openssl@3"
  depends_on "liboqs"

  def install
    system "make", "PREFIX=#{prefix}", "install"
    # Optional shell completions:
    bash_completion.install "completions/qsafe.bash" => "qsafe"
    zsh_completion.install "completions/_qsafe"
  end

  test do
    # keygen -> encrypt -> decrypt round-trip with a non-interactive passphrase.
    ENV["QSAFE_PASSPHRASE"] = "brew-test-pass"
    (testpath/"msg.txt").write("homebrew test\n")
    system bin/"qsafe", "keygen", "--key-file", testpath/"k.bin"
    system bin/"qsafe", "encrypt", "--key-file", testpath/"k.bin",
           testpath/"msg.txt", testpath/"msg.qsafe"
    system bin/"qsafe", "decrypt", "--key-file", testpath/"k.bin",
           testpath/"msg.qsafe", testpath/"out.txt"
    assert_equal "homebrew test\n", (testpath/"out.txt").read
  end
end
