require 'spec_helper'

RSpec.describe LibSSH::Channel do
  let(:session) do
    @session = LibSSH::Session.new
    @session.host = SshHelper.host
    @session.port = DockerHelper.port
    @session.user = SshHelper.user
    @session.connect
    @session.userauth_password(SshHelper.password)
    @session
  end

  let(:channel) { described_class.new(session) }

  after do
    @session&.disconnect
    @session = nil
  end

  describe '#open_session' do
    context 'without connected session' do
      it 'raises an error' do
        channel = described_class.new(LibSSH::Session.new)
        expect { channel.open_session { :ng } }.to raise_error(ArgumentError)
      end
    end

    context 'with valid condition' do
      it 'returns the block result' do
        expect(channel.open_session { :ok }).to eq(:ok)
      end
    end
  end

  describe '#request_exec' do
    context 'with valid condition' do
      it 'succeeds' do
        channel.open_session do
          expect(channel.request_exec('true')).to be_nil
        end
      end

      it "doesn't allocate a TTY" do
        channel.open_session do
          expect(channel.request_exec('tty')).to be_nil
          expect(channel.get_exit_status).to eq(1)
        end
      end

      context 'with #request_pty' do
        it 'allocates a TTY' do
          channel.open_session do
            expect(channel.request_pty).to be_nil
            expect(channel.request_exec('tty')).to be_nil
            expect(channel.get_exit_status).to eq(0)
          end
        end
      end
    end
  end

  describe '#request_send_signal' do
    it 'sends a signal to the remote process' do
      before = Time.now
      channel.open_session do
        channel.request_exec('sleep 2')
        channel.request_send_signal('HUP')
        channel.wait(timeout: 1)
      end
      after = Time.now
      expect(after - before).to be < 1
    end
  end

  describe '#read_nonblocking' do
    context 'with valid condition' do
      it 'returns stdout' do
        channel.open_session do
          channel.request_exec('echo hello')
          stdout = ''
          stderr = ''
          until channel.eof?
            r = channel.read_nonblocking(64)
            if r
              stdout << r
            end
            r = channel.read_nonblocking(64, true)
            if r
              stderr << r
            end
          end
          expect(stdout).to eq("hello\n")
          expect(stderr).to eq('')
        end
      end

      it 'returns stderr' do
        channel.open_session do
          channel.request_exec('echo hello >&2')
          stdout = ''
          stderr = ''
          until channel.eof?
            r = channel.read_nonblocking(64)
            if r
              stdout << r
            end
            r = channel.read_nonblocking(64, true)
            if r
              stderr << r
            end
          end
          expect(stdout).to eq('')
          expect(stderr).to eq("hello\n")
        end
      end
    end
  end
end
