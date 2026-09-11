require "libssh/libssh_ruby"

module LibSSH
  class Session
    # Configure the session with a LibSSH::Options or its Hash equivalent.
    def initialize(options)
      options = Options.new(options) unless options.is_a? Options
      set_options(options)
    end
  end
end
