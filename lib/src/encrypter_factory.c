/**
 * @file encrypter_factory.c
 * @brief Implement of encrypter_factory.h
 *
 **/
#include <stdlib.h>
#include "encrypter_factory.h"
EncrypterFactory enc_api_factory_new(enc_api_encrypt_type_e type) {
	return NULL;
}
void enc_api_create_factory_free(EncrypterFactory this) {
	free(this);
}
