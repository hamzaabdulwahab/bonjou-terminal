class Bonjou < Formula
  desc "Terminal-based LAN chat and transfer application"
  homepage "https://github.com/hamzawahab/bonjou-terminal"
  version "1.0.3"

  on_macos do
    url "https://github.com/hamzaabdulwahab/bonjou-terminal/releases/download/v1.0.3/bonjou-macos.tar.gz"
    sha256 "6136674c6273ba994d41e375c3b5de9a24a265e35f1ac8b2b35bbe3b0847c437"
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
