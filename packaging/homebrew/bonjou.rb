class Bonjou < Formula
  desc "Terminal-based LAN chat and transfer application"
  homepage "https://github.com/hamzawahab/bonjou-terminal"
  version "1.0.1"

  on_macos do
    url "https://github.com/hamzaabdulwahab/bonjou-terminal/releases/download/v1.0.1/bonjou-macos.tar.gz"
    sha256 "174f3918dea94982f7424d00f213d7598f0f9e0f41901f4f1c7ebc40fbac3606"
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
