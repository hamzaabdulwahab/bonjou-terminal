class Bonjou < Formula
  desc "Terminal-based LAN chat and transfer application"
  homepage "https://github.com/hamzawahab/bonjou-terminal"
  version "1.0.9"

  on_macos do
  url "https://github.com/hamzaabdulwahab/bonjou-terminal/releases/download/v1.0.9/bonjou-macos.tar.gz"
  sha256 "3a5df10f7a75e38ce64fe3d7f57c6b5ebaa6cc3542b30f3c5d5f868ece567bdf"
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
