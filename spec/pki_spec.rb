require 'spec_helper'

RSpec.describe LibSSH::PKI do
  let(:privkey) do
    LibSSH::PKI.import_privkey_base64(File.read(SshHelper.identity_path))
  end

  describe '.import_privkey_base64' do
    it 'loads a LibSSH::Key' do
      expect(privkey).to be_a LibSSH::Key
      expect(privkey.type_str).to eq 'ssh-ed25519'
    end

    it 'raises ArgumentError on bad key' do
      expect { LibSSH::PKI.import_privkey_base64('dynamite') }.to raise_error ArgumentError
    end
  end

  describe ".import_pubkey_base64" do
    ed25519_data = "AAAAC3NzaC1lZDI1NTE5AAAAIPuI+rpberfNkVz6Gf4QiUKYz3erfLZ5B4WxBge4I9Ax"

    specify "on valid key" do
      pubkey = LibSSH::PKI.import_pubkey_base64(ed25519_data, "ssh-ed25519")
      expect(pubkey.type_str).to eq 'ssh-ed25519'
      expect(LibSSH::PKI.export_pubkey_base64(pubkey)).to eq ed25519_data
    end

    specify "on invalid type" do
      expect { LibSSH::PKI.import_pubkey_base64(ed25519_data, "ssh-bidon") }.to \
        raise_error ArgumentError, "Unknown key type: ssh-bidon."
    end

    specify "on invalid data" do
      expect { LibSSH::PKI.import_pubkey_base64("foobar", "ssh-ed25519") }.to \
        raise_error ArgumentError, "Invalid base64 public key."
    end
  end

  specify '.export_privkey_to_pubkey' do
    pubkey = LibSSH::PKI.export_privkey_to_pubkey(privkey)
    expect(pubkey.type_str).to eq 'ssh-ed25519'
    expect(LibSSH::PKI.export_pubkey_base64(pubkey)).to eq \
      'AAAAC3NzaC1lZDI1NTE5AAAAIPuI+rpberfNkVz6Gf4QiUKYz3erfLZ5B4WxBge4I9Ax'
  end
end
