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
      expect { build(host: "foo_bar") }.to raise_error ArgumentError, 'Invalid host: foo_bar'
    end
  end

  describe '#connect' do
    specify "host is required" do
      expect { build(host: nil).connect }.to raise_error LibSSH::Error
    end

    it "raises an exception on closed port" do
      expect { build(port: 2).connect }.to raise_error LibSSH::Error
    end
  end

  describe '#userauth_list' do
    before do
      session.connect
    end

    context 'without userauth_none' do
      it 'returns empty' do
        expect(session.userauth_list).to eq([])
      end
    end

    context 'with valid condition' do
      before do
        session.userauth_none
      end

      it 'returns available methods' do
        expect(session.userauth_list).to match_array(%i[publickey password interactive])
      end
    end
  end

  describe '#userauth_publickey' do
    before do
      session.connect
    end

    it 'accepts good keys' do
      identity = SshHelper.identity_path
      privkey = LibSSH::PKI.import_privkey_base64(File.read(identity))
      expect(session.userauth_publickey(privkey)).to eq(LibSSH::AUTH_SUCCESS)
    end
  end

  describe '#userauth_publickey_auto' do
    context 'without valid private key' do
      it 'is denied' do
        session.connect
        expect(session.userauth_publickey_auto).to eq(LibSSH::AUTH_DENIED)
      end
    end
  end

  describe '#userauth_password' do
    before do
      session.connect
    end

    context 'wrong password' do
      it 'is denied' do
        expect(session.userauth_password('12345')).to eq(LibSSH::AUTH_DENIED)
      end
    end

    context 'with valid password' do
      it 'access is granted' do
        expect(session.userauth_password(SshHelper.password)).to eq(LibSSH::AUTH_SUCCESS)
      end
    end
  end

  describe '#userauth_kbdint' do
    before do
      session.connect
    end

    def kbdint(password)
      loop do
        rc = session.userauth_kbdint
        return rc if rc != LibSSH::AUTH_INFO

        nprompts = session.userauth_kbdint_getnprompts
        expect(nprompts).to be <= 1
        session.userauth_kbdint_setanswer(0, password) if nprompts == 1
      end
    end

    context 'with wrong password' do
      it 'is denied' do
        expect(kbdint('12345')).to eq(LibSSH::AUTH_DENIED)
      end
    end

    context 'with valid password' do
      it 'access is granted' do
        expect(kbdint(SshHelper.password)).to eq(LibSSH::AUTH_SUCCESS)
      end
    end
  end
end
