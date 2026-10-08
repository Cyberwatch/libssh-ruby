require 'libssh/libssh_ruby'

module LibSSH
  class Key
    def self.new(data)
      if data.start_with?("-")
        PKI.import_privkey_base64(data)
      else
        type, base64 = data.split
        raise ArgumentError, "Malformed SSH key." if base64.nil?
        PKI.import_pubkey_base64(base64, type)
      end
    end

    # Return the hash in SHA1 in hexadecimal notation.
    # @return [String]
    # @see #sha1
    # @since 0.1.0
    def sha1_hex
      sha1.unpack('H*')[0].each_char.each_slice(2).map(&:join).join(':')
    end

    def to_publickey
      raise ArgumentError, "Not a private key." unless private?
      LibSSH::PKI.export_privkey_to_pubkey(self)
    end

    def to_s
      if private?
       raise NotImplementedError, "private key export"
      else
        "#{type} #{LibSSH::PKI.export_pubkey_base64(self)}"
      end
    end

    def ==(other)
      other = LibSSH::Key(other)
      self.private? == other.private?
        && self === other
    end
  end

  def self.Key(key) = key.is_a?(Key) ? key : Key.new(key)
end
