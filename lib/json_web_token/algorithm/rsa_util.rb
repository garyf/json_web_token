module JsonWebToken
  module Algorithm
    # Load encryption keys
    module RsaUtil

      module_function

      # Load an RSA private key from a pem file
      def private_key(path_to_keys, filename = 'private_key.pem')
        decoded_key(path_to_keys, filename)
      end

      # Load an RSA public key from a pem file
      def public_key(path_to_keys, filename = 'public_key.pem')
        decoded_key(path_to_keys, filename)
      end

      def decoded_key(path_to_keys, filename)
        OpenSSL::PKey::RSA.new(pem_read(path_to_keys, filename))
      end

      def pem_read(path_to_keys, filename)
        File.read(File.join(path_to_keys, filename))
      end

      private_class_method :decoded_key,
        :pem_read
    end
  end
end
