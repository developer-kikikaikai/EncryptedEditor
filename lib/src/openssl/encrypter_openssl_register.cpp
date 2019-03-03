#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include "encrypter_factory.hpp"
#include "encrypter_openssl_aes256cbc.hpp"
#include "encrypter_openssl_aria128cbc.hpp"
#include <stdio.h>

namespace encapi::openssl {

__attribute__((constructor))
static void encrypter_openssl_constructor() {
	static AES256CBCFactory aes256_cbc_factory;
	regist_encrypter(ENC_API_ENCRYPT_TYPE_AES256_CBC, &aes256_cbc_factory);

	static ARIA128CBCFactory aria128_cbc_factory;
	regist_encrypter(ENC_API_ENCRYPT_TYPE_ARIA128_CBC, &aria128_cbc_factory);
}
}
