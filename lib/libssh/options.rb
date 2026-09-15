require "libssh/libssh_ruby"

module LibSSH
  # Declarative options for LibSSH::Session.
  #
  #     LibSSH::Options.new(
  #       user: "alice",
  #       host: "localhost",
  #       port: 22,
  #       timeout: 5, # seconds
  #       key_exchange: "ecdh-sha2-nistp256,…",
  #       hmac_c_s: "hmac-sha2-512,…",
  #       hmac_s_c: "hmac-sha2-512,…",
  #       hostkeys: "ssh-rsa,…",
  #       publickey_accepted_types: "ssh-rsa,…",
  #       stricthostkeycheck: false,
  #     )
  #
  # See also libssh’s documentation for ssh_options_set.
  #
  class Options
    attr_accessor :user, :host, :port, :timeout, :key_exchange, :hmac_c_s,
                  :hmac_s_c, :hostkeys, :publickey_accepted_types,
                  :stricthostkeycheck

    def initialize(attrs)
      attrs.each do |key, value|
        send("#{key}=", value)
      end
    end
  end
end
