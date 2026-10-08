require "spec_helper"

RSpec.describe LibSSH::Key do
  it "cannot be manually allocated" do
    expect { described_class.allocate }.to raise_error TypeError
  end

  specify "casting" do
    key = LibSSH::Key(File.read("spec/id_ed25519"))
    expect(key).to be_a LibSSH::Key
    expect(LibSSH::Key(key)).to be_a LibSSH::Key
  end

  describe "#fingerprint" do
    specify "on public key" do
      key_data = File.read("spec/id_ed25519.pub")
      expect(LibSSH::Key.new(key_data).fingerprint).to eq "SHA256:bPxEQjW+WV8/G39Fcylc0ANn/m/e3v7XZuoaN56Qhzw"
    end

    specify "on private key" do
      key_data = File.read("spec/id_ed25519")
      expect(LibSSH::Key.new(key_data).fingerprint).to eq "SHA256:bPxEQjW+WV8/G39Fcylc0ANn/m/e3v7XZuoaN56Qhzw"
    end
  end

  describe "#to_publickey" do
    specify "on a private key" do
      privkey = LibSSH::Key.new(File.read("spec/id_ed25519"))
      pubkey  = LibSSH::Key.new(File.read("spec/id_ed25519.pub"))
      expect(privkey.to_publickey).to eq pubkey
    end

    specify "on a public key" do
      pubkey = LibSSH::Key.new(File.read("spec/id_ed25519.pub"))
      expect { pubkey.to_publickey }.to raise_error ArgumentError, "Not a private key."
    end
  end

  describe "#to_s" do
    specify "on public key" do
      key_data = File.read("spec/id_ed25519.pub")
      expect(LibSSH::Key.new(key_data).to_s).to eq key_data.chomp
    end

    specify "on private key" do
      key_data = File.read("spec/id_ed25519")
      expect { LibSSH::Key.new(key_data).to_s }.to raise_error NotImplementedError
    end
  end

  specify "#===" do
    privkey = LibSSH::Key.new(File.read("spec/id_ed25519"))
    pubkey  = LibSSH::Key.new(File.read("spec/id_ed25519.pub"))
    other   = LibSSH::Key.new(File.read("spec/ssh_host_ed25519_key"))

    expect(pubkey  === pubkey ).to be true
    expect(pubkey  === privkey).to be true
    expect(privkey === privkey).to be true

    expect(pubkey  === other).to be false
    expect(privkey === other).to be false
  end

  specify "#==" do
    privkey = LibSSH::Key.new(File.read("spec/id_ed25519"))
    pubkey  = LibSSH::Key.new(File.read("spec/id_ed25519.pub"))

    expect(pubkey  == pubkey ).to be true
    expect(pubkey  == privkey).to be false
    expect(pubkey  != privkey).to be true
    expect(privkey == privkey).to be true
  end
end
