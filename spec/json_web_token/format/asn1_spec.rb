require 'json_web_token/format/asn1'

module JsonWebToken
  module Format
    describe Asn1 do
      context 'w bytes' do
        let(:der) { der_bytes.map(&:chr).join }
        let(:signature) { signature_bytes.map(&:chr).join }
        shared_examples_for '#der_to_signature' do
          it 'converts' do
            expect(signature.bytes.length).to eql signature_byte_count
            expect(Asn1.der_to_signature(der, sha_bits).bytes).to eql signature_bytes
          end
        end

        shared_examples_for '#signature_to_der' do
          it 'converts' do
            expect(Asn1.signature_to_der(signature, sha_bits).bytes).to eql der_bytes
          end
        end

        shared_examples_for 'w/o valid signature' do
          let(:signature_invalid) { (signature_bytes + [123]).map(&:chr).join }
          it '#signature_to_der raises' do
            expect { Asn1.signature_to_der(signature_invalid, sha_bits) }
              .to raise_error(RuntimeError, 'Invalid signature length')
          end
        end

        context 'for ES256' do
          let(:sha_bits) { '256' }
          let(:der_bytes) { [48, 69, 2, 32, 39, 115, 251, 5, 254, 60, 42, 53, 128, 68, 123, 82,
            222, 136, 26, 167, 246, 163, 233, 216, 206, 122, 106, 141, 43, 143, 137, 3, 88, 196,
            235, 161, 2, 33, 0, 143, 213, 54, 244, 194, 216, 188, 161, 77, 28, 87, 205, 16, 160,
            11, 125, 21, 62, 206, 233, 242, 201, 149, 152, 53, 25, 103, 6, 4, 56, 193, 161] }
          let(:signature_bytes) { [39, 115, 251, 5, 254, 60, 42, 53, 128, 68, 123, 82, 222, 136,
            26, 167, 246, 163, 233, 216, 206, 122, 106, 141, 43, 143, 137, 3, 88, 196, 235, 161,
            143, 213, 54, 244, 194, 216, 188, 161, 77, 28, 87, 205, 16, 160, 11, 125, 21, 62,
            206, 233, 242, 201, 149, 152, 53, 25, 103, 6, 4, 56, 193, 161] }
          let(:signature_byte_count) { 64 }
          it_behaves_like '#der_to_signature'
          it_behaves_like '#signature_to_der'
          it_behaves_like 'w/o valid signature'

          describe 'invalid sha_bits' do
            let(:invalid_sha_bits) { '257' }
            it '#der_to_signature raises' do
              expect { Asn1.der_to_signature(der, invalid_sha_bits) }
                .to raise_error(RuntimeError, 'Invalid sha_bits')
            end

            it '#signature_to_der raises' do
              expect { Asn1.signature_to_der(signature, invalid_sha_bits) }
                .to raise_error(RuntimeError, 'Invalid sha_bits')
            end
          end
        end

        context 'for ES384' do
          let(:sha_bits) { '384' }
          let(:der_bytes) { [48, 101, 2, 48, 22, 221, 123, 224, 5, 100, 163, 31, 98, 78, 240,
            249, 85, 126, 120, 130, 228, 123, 69, 2, 21, 65, 249, 229, 151, 208, 186, 162, 31,
            149, 42, 165, 134, 214, 197, 176, 120, 10, 205, 247, 176, 19, 2, 156, 112, 89, 58,
            234, 2, 49, 0, 255, 43, 120, 92, 206, 84, 88, 29, 109, 225, 254, 162, 37, 255, 127,
            231, 37, 178, 36, 173, 225, 201, 121, 154, 43, 122, 229, 114, 50, 83, 69, 243, 143,
            248, 89, 109, 136, 233, 223, 148, 137, 226, 96, 78, 166, 141, 222, 236] }
          let(:signature_bytes) { [22, 221, 123, 224, 5, 100, 163, 31, 98, 78, 240, 249, 85,
            126, 120, 130, 228, 123, 69, 2, 21, 65, 249, 229, 151, 208, 186, 162, 31, 149, 42,
            165, 134, 214, 197, 176, 120, 10, 205, 247, 176, 19, 2, 156, 112, 89, 58, 234, 255,
            43, 120, 92, 206, 84, 88, 29, 109, 225, 254, 162, 37, 255, 127, 231, 37, 178, 36,
            173, 225, 201, 121, 154, 43, 122, 229, 114, 50, 83, 69, 243, 143, 248, 89, 109, 136,
            233, 223, 148, 137, 226, 96, 78, 166, 141, 222, 236] }
          let(:signature_byte_count) { 96 }
          it_behaves_like '#der_to_signature'
          it_behaves_like '#signature_to_der'
          it_behaves_like 'w/o valid signature'
        end

        context 'for ES512' do
          let(:sha_bits) { '512' }
          let(:der_bytes) { [48, 129, 135, 2, 66, 0, 173, 236, 131, 242, 12, 189, 123, 8, 129,
            2, 239, 202, 73, 168, 134, 216, 173, 241, 30, 1, 216, 177, 69, 61, 2, 196, 126, 145,
            132, 172, 174, 210, 133, 191, 50, 57, 239, 229, 201, 118, 197, 62, 197, 62, 128,
            143, 82, 84, 251, 80, 18, 196, 194, 198, 62, 144, 16, 149, 26, 67, 3, 215, 235, 179,
            146, 2, 65, 40, 137, 198, 254, 15, 50, 214, 252, 43, 65, 203, 163, 140, 204, 66,
            159, 53, 125, 184, 29, 24, 189, 249, 21, 64, 109, 87, 100, 165, 139, 83, 129, 190,
            121, 180, 86, 241, 83, 238, 39, 63, 25, 247, 253, 130, 153, 47, 27, 138, 164, 221,
            25, 151, 135, 144, 84, 240, 46, 59, 94, 99, 147, 138, 103, 67] }
          let(:signature_bytes) { [0, 173, 236, 131, 242, 12, 189, 123, 8, 129, 2, 239, 202, 73,
            168, 134, 216, 173, 241, 30, 1, 216, 177, 69, 61, 2, 196, 126, 145, 132, 172, 174,
            210, 133, 191, 50, 57, 239, 229, 201, 118, 197, 62, 197, 62, 128, 143, 82, 84, 251,
            80, 18, 196, 194, 198, 62, 144, 16, 149, 26, 67, 3, 215, 235, 179, 146, 0, 40, 137,
            198, 254, 15, 50, 214, 252, 43, 65, 203, 163, 140, 204, 66, 159, 53, 125, 184, 29,
            24, 189, 249, 21, 64, 109, 87, 100, 165, 139, 83, 129, 190, 121, 180, 86, 241, 83,
            238, 39, 63, 25, 247, 253, 130, 153, 47, 27, 138, 164, 221, 25, 151, 135, 144, 84,
            240, 46, 59, 94, 99, 147, 138, 103, 67] }
          let(:signature_byte_count) { 132 }
          it_behaves_like '#der_to_signature'
          it_behaves_like '#signature_to_der'
          it_behaves_like 'w/o valid signature'
        end
      end
    end
  end
end
