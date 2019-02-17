/**
 * @file encrypt_api.c
 * @brief Implement of encrypt_api.h main
 *
 **/
#include <stdlib.h>
#include <stdbool.h>
#include "encrypter_factory.h"

static int enc_api_encrypt_action(enc_api_encrypt_type_e type, const char *src_buf, char **result_buf, bool is_enctype) {
	int result_len = -1;
	EncrypterFactory instance=NULL;
	EncrypterIF encrypter=NULL;

	instance = enc_api_factory_new(type);
	if(!instance) goto end;

	encrypter = instance->create();
	if(!encrypter) goto end;

	if(is_enctype) {
		result_len = encrypter->encrypt(src_buf, result_buf);
	} else {
		result_len = encrypter->decrypt(src_buf, result_buf);
	}

end:
	if(!instance) {
		if(!encrypter) instance->delete(encrypter);
		enc_api_create_factory_free(instance);
	}
	return result_len;
}

int enc_api_encrypt(enc_api_encrypt_type_e type, const char *src_buf, char ** result_buf) {
	return enc_api_encrypt_action(type, src_buf, result_buf, true);
}

int enc_api_decrypt(enc_api_encrypt_type_e type, const char *src_buf, char ** result_buf) {
	return enc_api_encrypt_action(type, src_buf, result_buf, false);
}
