#include "encrypter_openssl_aes256cbc.hpp"
#include "encrypter_openssl_aria128cbc.hpp"
#include "encrypter_openssl_camellia256cbc.hpp"
#include "encrypter_openssl_chacha20.hpp"
#include "encrypter_openssl_chacha20_poly1305.hpp"

namespace encapi{namespace openssl {

__attribute__((constructor))
static void encrypter_openssl_constructor() {
	static AES256CBCFactory aes256_cbc_factory;
	regist_encrypter(ENC_API_ENCRYPT_TYPE_AES256_CBC, &aes256_cbc_factory);

	static ARIA128CBCFactory aria128_cbc_factory;
	regist_encrypter(ENC_API_ENCRYPT_TYPE_ARIA128_CBC, &aria128_cbc_factory);

	static CHACHA20Factory camellia256_cbc_factory;
	regist_encrypter(ENC_API_ENCRYPT_TYPE_CAMELLIA256_CBC, &camellia256_cbc_factory);

	static CHACHA20Factory chacha20_factory;
	regist_encrypter(ENC_API_ENCRYPT_TYPE_CHACHA20, &chacha20_factory);

	static CHACHA20_POLY1305Factory chacha20_poly1305_factory;
	regist_encrypter(ENC_API_ENCRYPT_TYPE_CHACHA20_POLY1305, &chacha20_poly1305_factory);
}
}}//namespace
