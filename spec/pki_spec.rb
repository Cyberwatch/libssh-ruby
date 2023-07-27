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

  specify '.export_privkey_to_pubkey' do
    pubkey = LibSSH::PKI.export_privkey_to_pubkey(privkey)
    expect(pubkey.type_str).to eq 'ssh-ed25519'
  end
end
