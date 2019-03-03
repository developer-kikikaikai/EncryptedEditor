/**
 * @file encrypt_api.cpp
 * @brief Implement of encrypt_api.h main
 *
 **/
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "encrypter_factory.hpp"

static int enc_api_encrypt_action(enc_api_encrypt_type_e type, const unsigned char *src_buf, int src_len, unsigned char **result_buf, bool is_enctype) {
	int result_len = -1;
	encapi::EncrypterFactory * factory=NULL;
	fprintf(stderr, "enc_api_encrypt_action\n");
	factory = encapi::get_factory(type);
	if(!factory) return -1;

	encapi::EncrypterIF * encrypter = factory->create_if();
	if(!encrypter) return -1;

	if(is_enctype) {
		result_len = encrypter->encrypt(src_buf, src_len, result_buf);
	} else {
		result_len = encrypter->decrypt(src_buf, src_len, result_buf);
	}

	factory->delete_if(encrypter);
	return result_len;
}

int enc_api_encrypt(enc_api_encrypt_type_e type, const unsigned char *src_buf, int src_len, unsigned char ** result_buf) {
	return enc_api_encrypt_action(type, src_buf, src_len, result_buf, true);
}

int enc_api_decrypt(enc_api_encrypt_type_e type, const unsigned char *src_buf, int src_len, unsigned char ** result_buf) {
	return enc_api_encrypt_action(type, src_buf, src_len, result_buf, false);
}
