class Bonjou < Formula
  desc "Terminal-based LAN chat and transfer application"
  homepage "https://github.com/hamzawahab/bonjou-terminal"
  version "1.0.8"

  on_macos do
  url "https://github.com/hamzaabdulwahab/bonjou-terminal/releases/download/v1.0.8/bonjou-macos.tar.gz"
  sha256 "cef0b80fa12bcb75321955ff36a290cab7ef90f06ca7c1846d78aa33ad10d107"
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
