/**
 * @file encrypter_factory.c
 * @brief Implement of encrypter_factory.h
 *
 **/
#include <stdlib.h>
#include <stdio.h>
#include "encrypter_factory.hpp"
#include "encrypter_backend.hpp"

namespace encapi {
EncrypterFactory* get_factory(enc_api_encrypt_type_e type) {
	return default_encrypter_backend().find_factory(type);
}
}
