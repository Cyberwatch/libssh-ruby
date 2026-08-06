# frozen_string_literal: true

require 'English'
require 'fileutils'
require 'json'
require 'libssh'

module DockerHelper
  SPAWN_SSHD = <<~'SH'
    docker run --detach \
      -e PUBLIC_KEY_FILE=/spec/id_ed25519.pub \
      -e PASSWORD_ACCESS=true \
      -e USER_NAME=alice \
      -e USER_PASSWORD=alice \
      -v ./spec:/spec:ro \
      -v ./spec/sshd_config:/config/sshd/sshd_config.d/99-override.conf:ro \
      --publish-all \
      lscr.io/linuxserver/openssh-server:latest
  SH

  class << self
    def start
      @container_id = IO.popen(SPAWN_SSHD, &:read)
      unless $CHILD_STATUS.success?
        raise 'Cannot start Docker container'
      end
      @container_id.chomp!

      container = JSON.parse(IO.popen(['docker', 'inspect', @container_id], &:read))[0]
      @port = container['NetworkSettings']['Ports']['2222/tcp'][0]['HostPort'].to_i
      wait_for_ready
      @host_key = IO.popen(['docker', 'exec', @container_id, 'cat', '/config/ssh_host_keys/ssh_host_ed25519_key.pub'], &:read)
    end

    def stop
      unless system('docker', 'stop', '-t', '0', @container_id, out: File::NULL)
        warn "Cannot stop Docker container #{@container_id}"
      end
    end

    attr_reader :port, :host_key

    private

    def wait_for_ready
      10.times do
        sleep 1
        return if system('docker', 'exec', @container_id,
                         'ssh', '-i', '/spec/id_ed25519', '-oStrictHostKeyChecking=no', '-p2222', 'alice@127.0.0.1',
                         'exit', '0',
                         err: File::NULL)
      end
      raise 'Failed to connect to the Docker container'
    end
  end
end

module SshHelper
  class << self
    def host
      'localhost'
    end

    def user
      'alice'
    end

    def password
      'alice'
    end

    def default_key_type
      @default_key_type ||=
        if Gem::Version.new(LibSSH.version.split('/').first) >= Gem::Version.new('0.7.0')
          'ed25519'
        else
          'ecdsa'
        end
    end

    def identity_path
      File.join(__dir__, "id_#{default_key_type}")
    end

    def empty_known_hosts
      File.join(__dir__, 'known_hosts.empty')
    end

    def absent_known_hosts
      File.join(__dir__, 'known_hosts.enoent')
    end

    def valid_known_hosts
      File.join(__dir__, 'known_hosts.valid')
    end

    def invalid_known_hosts
      File.join(__dir__, 'known_hosts.invalid')
    end

    def prepare_known_hosts
      FileUtils.rm_f(absent_known_hosts)
      File.open(empty_known_hosts, 'w') {}

      File.open(valid_known_hosts, 'w') do |f|
        f.puts("[#{host}]:#{DockerHelper.port} #{DockerHelper.host_key}")
      end
      File.open(invalid_known_hosts, 'w') do |f|
        f.puts("[#{host}]:#{DockerHelper.port} #{DockerHelper.host_key.sub('A', 'B')}")
      end
    end
  end
end

RSpec.configure do |config|
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end

  config.filter_run :focus
  config.run_all_when_everything_filtered = true

  config.example_status_persistence_file_path = 'spec/examples.txt'

  config.disable_monkey_patching!

  config.warnings = true

  config.profile_examples = 10

  config.order = :random
  Kernel.srand config.seed

  config.before :suite do
    DockerHelper.start
  end

  config.after :suite do
    DockerHelper.stop
  end

  config.before :each do
    SshHelper.prepare_known_hosts
  end
end
