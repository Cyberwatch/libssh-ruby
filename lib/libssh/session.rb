require "libssh/libssh_ruby"

module LibSSH
  class Session
    def initialize
      @proxyjump_hosts = []
    end

    def add_proxy_jump(host)
      raise ArgumentError, "Jump host must not contain commas: #{host.inspect}" if host.include?(",")
      @proxyjump_hosts << host
      set_option("proxy jump", C::SSH_OPTIONS_PROXYJUMP, @proxyjump_hosts.join(","))
    end

    private

    def set_option(name, type, value)
      C::ssh_options_set(self, type, value)
    rescue Error
      raise ArgumentError, "Invalid #{name}: #{value.inspect}"
    end
  end
end
