#include "encrypter_openssl_buffer.hpp"
#include "encrypter_openssl.hpp"
#include "encrypter_openssl_aes256cbc.hpp"

namespace encapi::openssl {
#define AES256CBC_PADDING (16)
static class BaseAllocater encode_allocater_g = BaseAllocater(AES256CBC_PADDING);
static class BaseAllocater decode_allocater_g = BaseAllocater(0);

class EncrypterAES256CBC : public EncrypterOpenssl {
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
		return EVP_aes_256_cbc();
	}
public:
	EncrypterAES256CBC() {
		enc_allocater = &encode_allocater_g;
		dec_allocater = &decode_allocater_g;
	}
	~EncrypterAES256CBC() {
	}
};

EncrypterIF * AES256CBCFactory::create_if(void) {
	return new EncrypterAES256CBC();
}
void AES256CBCFactory::delete_if(EncrypterIF * instance) {
	delete (EncrypterAES256CBC *)instance;
}
}
