require "libssh/libssh_ruby"

module LibSSH
  # Declarative options for LibSSH::Session.
  #
  #     LibSSH::Options.new(
  #       user: "alice",
  #       host: "localhost",
  #       port: 22,
  #     )
  #
  class Options
    attr_accessor :user, :host, :port

    def initialize(attrs)
      attrs.each do |key, value|
        send("#{key}=", value)
      end
    end
  end
end
