#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include "encrypter_factory.hpp"
#include <stdio.h>

namespace encapi {
static EncrypterIF * openssl_aes256_cbc_create_if(void);
static void openssl_aes256_cbc_delete_if(EncrypterIF *);
static int openssl_aes256_cbc_encrypt(const unsigned char *src_buf, int src_len, unsigned char **result_buf);
static int openssl_aes256_cbc_decrypt(const unsigned char *src_buf, int src_len, unsigned char **result_buf);
static const unsigned char * openssl_privatekey(void);
static const unsigned char * openssl_iv(void);

__attribute__((constructor))
static void encrypter_openssl_constructor() {
	static EncrypterFactory aes256_cbc_factory ={.create_if=openssl_aes256_cbc_create_if, .delete_if=openssl_aes256_cbc_delete_if};
	regist_encrypter(ENC_API_ENCRYPT_TYPE_OPENSSL_AES256_ECB, &aes256_cbc_factory);
}

static int openssl_handle_err() {
	ERR_print_errors_fp(stderr);
	return -1;
}

static int openssl_aes256_cbc_encrypt(const unsigned char *src_buf, int src_len, unsigned char **result_buf) {
	EVP_CIPHER_CTX * ctx;

	fprintf(stderr, "%s enter\n", __FUNCTION__);
	if(!(ctx = EVP_CIPHER_CTX_new())) return openssl_handle_err();

	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, openssl_privatekey(), openssl_iv())) return openssl_handle_err();

	*result_buf = (unsigned char *)calloc(1, 8192);
	int buf_len=0, result_len=0;
	if(1 != EVP_EncryptUpdate(ctx, *result_buf, &buf_len, src_buf, src_len) ) return openssl_handle_err();
	result_len = buf_len;

	if(1 != EVP_EncryptFinal_ex(ctx, *result_buf + buf_len, &buf_len)) return openssl_handle_err();
	result_len += buf_len;
	memset((*result_buf) + result_len, 0, 8192 - result_len);

	EVP_CIPHER_CTX_free(ctx);
	fprintf(stderr, "%s exit %d\n", __FUNCTION__, result_len);
	return result_len;
}

static int openssl_aes256_cbc_decrypt(const unsigned char *src_buf, int src_len, unsigned char **result_buf) {
	EVP_CIPHER_CTX * ctx;

	fprintf(stderr, "%s enter\n", __FUNCTION__);
	if(!(ctx = EVP_CIPHER_CTX_new())) return openssl_handle_err();

	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, openssl_privatekey(), openssl_iv())) return openssl_handle_err();

	*result_buf = (unsigned char *)calloc(1, 8192);
	int buf_len=0, result_len=0;
	if(1 != EVP_DecryptUpdate(ctx, *result_buf, &buf_len, src_buf, src_len) ) return openssl_handle_err();
	result_len = buf_len;

	if(1 != EVP_DecryptFinal_ex(ctx, *result_buf + buf_len, &buf_len)) return openssl_handle_err();
	result_len += buf_len;
	memset((*result_buf) + result_len, 0, 8192 - result_len);

	EVP_CIPHER_CTX_free(ctx);
	fprintf(stderr, "%s exit %d\n", __FUNCTION__, result_len);

	return result_len;
}

__attribute__((destructor))
static void destructor() {
}

static const unsigned char * openssl_privatekey(void) {
	static const unsigned char key[]="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	return key;
}
static const unsigned char * openssl_iv(void) {
	static const unsigned char iv[]="1234567890123456";
	return iv;
}

static EncrypterIF * openssl_aes256_cbc_create_if(void) {
	EncrypterIF * instance = new EncrypterIF();
	instance->encrypt = openssl_aes256_cbc_encrypt;
	instance->decrypt = openssl_aes256_cbc_decrypt;
	return instance;
}

static void openssl_aes256_cbc_delete_if(EncrypterIF *instance) {
	delete instance;
}
}
