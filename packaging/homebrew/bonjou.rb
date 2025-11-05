class Bonjou < Formula
  desc "Terminal-based LAN chat and transfer application"
  homepage "https://github.com/hamzawahab/bonjou-terminal"
  version "1.0.2"

  on_macos do
    url "https://github.com/hamzaabdulwahab/bonjou-terminal/releases/download/v1.0.2/bonjou-macos.tar.gz"
    sha256 "4b1d99132152a4a58e4ea4c1bddb1ac414902f2f360340f157dcc808c7afc6df"
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
