/**
 * @file encrypter_backend.hpp
 * @brief Backend interface used to resolve encrypter factories.
 */
#ifndef ENCRYPTER_BACKEND_H_
#define ENCRYPTER_BACKEND_H_

#include "encrypter_factory.hpp"

namespace encapi {

struct EncrypterBackend {
	virtual EncrypterFactory * find_factory(enc_api_encrypt_type_e type) const = 0;
	virtual ~EncrypterBackend() {}
};

EncrypterBackend& default_encrypter_backend();

}
#endif/*ENCRYPTER_BACKEND_H_*/
