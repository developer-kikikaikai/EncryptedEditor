#include "encrypter_openssl_buffer.hpp"
#include "encrypter_openssl.hpp"
#include "encrypter_openssl_aria128cbc.hpp"

namespace encapi::openssl {
#define ARIA128CBC_PADDING (8)
static class BaseAllocater encode_allocater_g = BaseAllocater(ARIA128CBC_PADDING);
static class BaseAllocater decode_allocater_g = BaseAllocater(0);

class EncrypterARIA128CBC : public EncrypterOpenssl {
private:
	const unsigned char * _get_key(void) {
		static const unsigned char key[]="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
		return key;
	}
	const unsigned char * _get_iv(void) {
		static const unsigned  char iv[]= "1234567890123456";
		return iv;
	}

	const EVP_CIPHER * _get_evp_cipher() {
		return EVP_aria_128_cbc();
	}
public:
	EncrypterARIA128CBC() {
		enc_allocater = &encode_allocater_g;
		dec_allocater = &decode_allocater_g;
	}
	~EncrypterARIA128CBC() {
	}
};

EncrypterIF * ARIA128CBCFactory::create_if(void) {
	return new EncrypterARIA128CBC();
}
void ARIA128CBCFactory::delete_if(EncrypterIF * instance) {
	delete (EncrypterARIA128CBC *)instance;
}
}
