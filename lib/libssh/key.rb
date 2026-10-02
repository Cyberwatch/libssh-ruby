require 'libssh/libssh_ruby'

module LibSSH
  class Key
    # Return the hash in SHA1 in hexadecimal notation.
    # @return [String]
    # @see #sha1
    # @since 0.1.0
    def sha1_hex
      sha1.unpack('H*')[0].each_char.each_slice(2).map(&:join).join(':')
    end

    def to_s
      if public?
        "#{type_str} #{LibSSH::PKI.export_pubkey_base64(self)}"
      else
       raise NotImplementedError "private key export"
      end
    end
  end
end
