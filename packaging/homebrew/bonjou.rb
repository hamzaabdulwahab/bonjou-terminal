class Bonjou < Formula
  desc "Terminal-based LAN chat and transfer application"
  homepage "https://github.com/hamzawahab/bonjou-terminal"
  version "1.0.6"

  on_macos do
  url "https://github.com/hamzaabdulwahab/bonjou-terminal/releases/download/v1.0.6/bonjou-macos.tar.gz"
  sha256 "ba03865464efe1ac2efb249a7adb305ad0b85a29f424e99594769c53863dedac"
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
