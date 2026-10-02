require 'spec_helper'

RSpec.describe LibSSH::Session do
  def session
    @session ||= build
  end

  def build(options = {})
    @session = described_class.new(
      host: SshHelper.host,
      port: DockerHelper.port,
      user: SshHelper.user,
      stricthostkeycheck: false,
      **options,
    )
  end

  after do
    @session&.disconnect
    @session = nil
  end

  describe "#initialize" do
    specify "user is nullable" do
      expect { build(user: nil) }.not_to raise_error
    end

    it "raises an exception on bad host" do
      expect { build(host: "foo_bar") }.to raise_error ArgumentError, "Invalid host."
    end

    specify "full options" do
      options = {
        timeout: 5, # seconds
        key_exchange: "ecdh-sha2-nistp256",
        hmac_c_s: "hmac-sha2-512",
        hmac_s_c: "hmac-sha2-512",
        hostkeys: "ssh-rsa",
        publickey_accepted_types: "ssh-rsa",
      }
      expect { build(options) }.not_to raise_error
    end
  end

  describe '#connect' do
    specify "host is required" do
      expect { build(host: nil).connect }.to raise_error LibSSH::Error, "Hostname required"
    end

    it "raises an exception on closed port" do
      expect { build(port: 2).connect }.to raise_error LibSSH::Error, "Connection refused"
    end

    specify "public key" do
      expect { build(key: "bad key").connect }.to raise_error \
        ArgumentError, "Invalid base64 private key."

      expect { build(key: File.read("spec/ssh_host_ed25519_key")).connect }.to raise_error \
        LibSSH::Error, /\AAuthentication by key failed./

      expect { build(key: File.read("spec/id_ed25519")).connect }.not_to raise_error
    end

    specify "password" do
      expect { build(password: "12345").connect }.to raise_error \
        LibSSH::Error, /\AKeyboard-interactive authentication with password failed./

      expect { build(password: SshHelper.password).connect }.not_to raise_error
    end

    specify "automatic" do
      expect { build.connect }.to raise_error LibSSH::Error, /\AAutomatic authentication failed/
    end

    specify "host key checking" do
      expect { build(password: SshHelper.password, stricthostkeycheck: true).connect }.to \
        raise_error LibSSH::Error, "Server missing from known hosts."
    end

    specify "proxy jumps" do
      credentials = { user: SshHelper.user, password: SshHelper.password }
      options =   { host: "127.0.0.1",    port: 2222,              **credentials, stricthostkeycheck: false }
      good_jump = { host: SshHelper.host, port: DockerHelper.port, **credentials, stricthostkeycheck: false }
      bad_jump = { **good_jump, password: "bad" }
      expect { build(**options, proxy_jump: good_jump).connect }.not_to raise_error
      expect { build(**options, proxy_jump: bad_jump).connect }.to raise_error LibSSH::Error
    end
  end

  specify "#get_server_publickey" do
    session = build(password: SshHelper.password)
    session.connect
    expect(session.get_server_publickey.to_s).to eq File.read("spec/ssh_host_ed25519_key.pub").chomp
  end
end
