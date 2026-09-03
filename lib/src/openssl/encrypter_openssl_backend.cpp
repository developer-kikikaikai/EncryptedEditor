#include "encrypter_openssl_backend.hpp"
#include "encrypter_openssl_aes256cbc.hpp"
#include "encrypter_openssl_aria128cbc.hpp"
#include "encrypter_openssl_camellia256cbc.hpp"
#include "encrypter_openssl_chacha20.hpp"
#include "encrypter_openssl_chacha20_poly1305.hpp"

namespace encapi{namespace openssl {

EncrypterFactory * OpenSSLEncrypterBackend::find_factory(enc_api_encrypt_type_e type) const {
	switch (type) {
	case ENC_API_ENCRYPT_TYPE_AES256_CBC: {
		static AES256CBCFactory factory;
		return &factory;
	}
	case ENC_API_ENCRYPT_TYPE_ARIA128_CBC: {
		static ARIA128CBCFactory factory;
		return &factory;
	}
	case ENC_API_ENCRYPT_TYPE_CAMELLIA256_CBC: {
		static CAMELLIA256CBCFactory factory;
		return &factory;
	}
	case ENC_API_ENCRYPT_TYPE_CHACHA20: {
		static CHACHA20Factory factory;
		return &factory;
	}
	case ENC_API_ENCRYPT_TYPE_CHACHA20_POLY1305: {
		static CHACHA20_POLY1305Factory factory;
		return &factory;
	}
	default:
		return nullptr;
	}
}

}}//namespace
