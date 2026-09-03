/**
 * @file encrypter_openssl_backend.hpp
 * @brief OpenSSL implementation of the encrypter backend.
 */
#ifndef ENCRYPTER_OPENSSL_BACKEND_H_
#define ENCRYPTER_OPENSSL_BACKEND_H_

#include "encrypter_backend.hpp"

namespace encapi{namespace openssl {

class OpenSSLEncrypterBackend final : public EncrypterBackend {
public:
	EncrypterFactory * find_factory(enc_api_encrypt_type_e type) const override;
};

}}//namespace
#endif/*ENCRYPTER_OPENSSL_BACKEND_H_*/
