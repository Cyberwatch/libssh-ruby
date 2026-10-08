require "spec_helper"

RSpec.describe LibSSH::Options do
  describe "#host_publickey" do
    specify "with a public key" do
      options = described_class.new(host_publickey: File.read("spec/ssh_host_ed25519_key.pub"))
      expect(options.host_publickey).to be_a LibSSH::Key
    end

    specify "with a private key" do
      # Private keys contain the public key so ssh_key_is_public returns true.
      options = described_class.new(host_publickey: File.read("spec/ssh_host_ed25519_key"))
      expect(options.host_publickey).to be_a LibSSH::Key
    end

    specify "with invalid data" do
      expect { described_class.new(host_publickey: "boom") }.to \
        raise_error ArgumentError, "Malformed SSH key."
    end
  end

  describe "#key" do
    specify "with a private key" do
      options = described_class.new(key: File.read("spec/id_ed25519"))
      expect(options.key).to be_a LibSSH::Key
    end

    specify "with a public key" do
      expect { described_class.new(key: File.read("spec/id_ed25519.pub")) }.to \
        raise_error ArgumentError, "Not a private key."
    end

    specify "with invalid data" do
      expect { described_class.new(key: "boom") }.to \
        raise_error ArgumentError, "Malformed SSH key."
    end
  end
end
