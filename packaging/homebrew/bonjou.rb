class Bonjou < Formula
  desc "Terminal-based LAN chat and transfer application"
  homepage "https://github.com/hamzaabdulwahab/bonjou-cli"
  version "1.1.0"

  on_macos do
    url "https://github.com/hamzaabdulwahab/bonjou-cli/releases/download/v1.1.0/bonjou-macos"
    sha256 "REPLACE_WITH_V1_1_0_MACOS_SHA256"
  end

  def install
    bin.install "bonjou-macos" => "bonjou"
  end

  def caveats
    <<~EOS
      Bonjou expects UDP discovery on port 46320 and TCP messaging on port 46321.
      Ensure these ports are open on your firewall.
    EOS
  end

  test do
    pipe_output("#{bin}/bonjou", "@exit\n")
  end
end
