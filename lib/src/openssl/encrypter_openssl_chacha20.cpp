#include "encrypter_openssl_buffer.hpp"
#include "encrypter_openssl.hpp"
#include "encrypter_openssl_chacha20.hpp"
#include "encrypter_openssl_seed.hpp"

namespace encapi::openssl {
#define CHACHA20_PADDING (64)
static class BaseAllocater encode_allocater_g = BaseAllocater(CHACHA20_PADDING);
static class BaseAllocater decode_allocater_g = BaseAllocater(0);

class EncrypterCHACHA20 : public EncrypterOpenssl {
private:
	const unsigned char * _get_key(void) {
		return get_base_key();
	}
	const unsigned char * _get_iv(void) {
		return get_base_iv();
	}

	const EVP_CIPHER * _get_evp_cipher() {
		return EVP_chacha20();
	}
public:
	EncrypterCHACHA20() {
		enc_allocater = &encode_allocater_g;
		dec_allocater = &decode_allocater_g;
	}
	~EncrypterCHACHA20() {
	}
};

EncrypterIF * CHACHA20Factory::create_if(void) {
	return new EncrypterCHACHA20();
}
void CHACHA20Factory::delete_if(EncrypterIF * instance) {
	delete (EncrypterCHACHA20 *)instance;
}
}
