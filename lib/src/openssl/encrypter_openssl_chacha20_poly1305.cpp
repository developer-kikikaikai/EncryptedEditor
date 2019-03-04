#include "encrypter_openssl_buffer.hpp"
#include "encrypter_openssl.hpp"
#include "encrypter_openssl_chacha20_poly1305.hpp"
#include "encrypter_openssl_seed.hpp"

namespace encapi::openssl {
#define CHACHA20_POLY1305_PADDING (32)
static class BaseAllocater encode_allocater_g = BaseAllocater(CHACHA20_POLY1305_PADDING);
static class BaseAllocater decode_allocater_g = BaseAllocater(0);

class EncrypterCHACHA20_POLY1305 : public EncrypterOpenssl {
private:
	const unsigned char * _get_key(unsigned char *seed, int length) {
		return get_base_key(seed, length);
	}
	const unsigned char * _get_iv(unsigned char *seed, int length) {
		return get_base_iv(seed, length);
	}

	const EVP_CIPHER * _get_evp_cipher() {
		return EVP_chacha20_poly1305();
	}
public:
	EncrypterCHACHA20_POLY1305() {
		enc_allocater = &encode_allocater_g;
		dec_allocater = &decode_allocater_g;
	}
	~EncrypterCHACHA20_POLY1305() {
	}
};

EncrypterIF * CHACHA20_POLY1305Factory::create_if(void) {
	return new EncrypterCHACHA20_POLY1305();
}
void CHACHA20_POLY1305Factory::delete_if(EncrypterIF * instance) {
	delete (EncrypterCHACHA20_POLY1305 *)instance;
}
}
