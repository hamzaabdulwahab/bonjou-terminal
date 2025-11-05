class Bonjou < Formula
  desc "Terminal-based LAN chat and transfer application"
  homepage "https://github.com/hamzawahab/bonjou-terminal"
  version "1.0.4"

  on_macos do
    url "https://github.com/hamzaabdulwahab/bonjou-terminal/releases/download/v1.0.4/bonjou-macos.tar.gz"
    sha256 "3c4d2e9a63bda8fc869372c29b291451e80764839d63953f13902b47256e369c"
  end

  def install
    bin.install "bonjou"
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
