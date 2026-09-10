require "libssh/libssh_ruby"

module LibSSH
  class Channel
    def wait(timeout: nil)
      wait_timeout(timeout)
    end
  end
end
