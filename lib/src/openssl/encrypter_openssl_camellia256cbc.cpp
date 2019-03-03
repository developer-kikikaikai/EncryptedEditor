#include "encrypter_openssl_buffer.hpp"
#include "encrypter_openssl.hpp"
#include "encrypter_openssl_camellia256cbc.hpp"
#include "encrypter_openssl_seed.hpp"

namespace encapi::openssl {
#define CAMELLIA256CBC_PADDING (8)
static class BaseAllocater encode_allocater_g = BaseAllocater(CAMELLIA256CBC_PADDING);
static class BaseAllocater decode_allocater_g = BaseAllocater(0);

class EncrypterCAMELLIA256CBC : public EncrypterOpenssl {
private:
	const unsigned char * _get_key(void) {
		return get_base_key();
	}
	const unsigned char * _get_iv(void) {
		return get_base_iv();
	}

	const EVP_CIPHER * _get_evp_cipher() {
		return EVP_camellia_256_cbc();
	}
public:
	EncrypterCAMELLIA256CBC() {
		enc_allocater = &encode_allocater_g;
		dec_allocater = &decode_allocater_g;
	}
	~EncrypterCAMELLIA256CBC() {
	}
};

EncrypterIF * CAMELLIA256CBCFactory::create_if(void) {
	return new EncrypterCAMELLIA256CBC();
}
void CAMELLIA256CBCFactory::delete_if(EncrypterIF * instance) {
	delete (EncrypterCAMELLIA256CBC *)instance;
}
}
