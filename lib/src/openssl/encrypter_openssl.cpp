#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include "encrypter_factory.hpp"
#include "encrypter_openssl.hpp"

namespace encapi{namespace openssl {

static const char ENC_OPENSSL_SALT_TAG[] = "Salted_libcrypto_";
static const size_t ENC_OPENSSL_SALT_TAG_LEN = sizeof(ENC_OPENSSL_SALT_TAG) - 1;
static const size_t ENC_OPENSSL_RANDOM_SALT_LEN = 4;
static const size_t ENC_OPENSSL_SALT_LEN = ENC_OPENSSL_SALT_TAG_LEN +
	(ENC_OPENSSL_RANDOM_SALT_LEN * 2) + 1;

bool EncrypterOpenssl::get_salt(unsigned char *salt) {
	unsigned char random_salt[ENC_OPENSSL_RANDOM_SALT_LEN];
	if (RAND_bytes(random_salt, sizeof(random_salt)) != 1) return false;

	snprintf((char *)salt, ENC_OPENSSL_SALT_LEN, "%s%02x%02x%02x%02x",
		ENC_OPENSSL_SALT_TAG,
		random_salt[0], random_salt[1], random_salt[2], random_salt[3]);
	return true;
}

int EncrypterOpenssl::encrypt(const unsigned char *src_buf, int src_len, unsigned char **result_buf) {
	/*encrypting as https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption*/

	/*fail safe*/
	if(src_len == 0 || src_buf == NULL) return -1;

	/*initialize EVP_CIPHER_CTX*/
	EncrypterBuffer buffer(enc_allocater);

	buffer.allocate(src_len + ENC_OPENSSL_SALT_LEN + 1);

	unsigned char salt[ENC_OPENSSL_SALT_LEN + 1];
	if (!get_salt(salt)) return buffer._handle_err();

	if(1 != EVP_EncryptInit_ex(buffer.ctx, _get_evp_cipher(), NULL, _get_key(salt, ENC_OPENSSL_SALT_LEN), _get_iv(salt, ENC_OPENSSL_SALT_LEN))) return buffer._handle_err();

	unsigned char * buf = buffer.get();
	int result_len=0;
	int evp_len=0;
	if(1 != EVP_EncryptUpdate(buffer.ctx, buf, &evp_len, src_buf, src_len) ) return buffer._handle_err();
	result_len = evp_len;

	if(1 != EVP_EncryptFinal_ex(buffer.ctx, buf + evp_len, &evp_len)) return buffer._handle_err();
	result_len += evp_len;

	buffer.padding(result_len);

	memmove(buf+ENC_OPENSSL_SALT_LEN, buf, result_len);
	memcpy(buf, salt, ENC_OPENSSL_SALT_LEN);
	*result_buf = buffer.pop();
	return result_len + ENC_OPENSSL_SALT_LEN;
}

int EncrypterOpenssl::decrypt(const unsigned char *src_buf, int src_len, unsigned char **result_buf) {
	/*decrypting as https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption*/

	/*fail safe*/
	if(src_len < (int)ENC_OPENSSL_SALT_LEN || src_buf == NULL) return -1;

	/*check header*/
	unsigned char salt[ENC_OPENSSL_SALT_LEN+1]={0};
	memcpy(salt, src_buf, ENC_OPENSSL_SALT_LEN);
	if(strncmp(ENC_OPENSSL_SALT_TAG, (char *)salt, strlen(ENC_OPENSSL_SALT_TAG)) != 0) return -1;

	/*initialize EVP_CIPHER_CTX*/
	EncrypterBuffer buffer(dec_allocater);

	buffer.allocate(src_len + 1);

	if(1 != EVP_DecryptInit_ex(buffer.ctx, _get_evp_cipher(), NULL, _get_key(salt, ENC_OPENSSL_SALT_LEN), _get_iv(salt, ENC_OPENSSL_SALT_LEN))) return buffer._handle_err();

	unsigned char * buf = buffer.get();
	int result_len=0;
	int evp_len=0;
	if(1 != EVP_DecryptUpdate(buffer.ctx, buf, &evp_len, src_buf + ENC_OPENSSL_SALT_LEN, src_len - ENC_OPENSSL_SALT_LEN) ) return buffer._handle_err();
	result_len = evp_len;

	if(1 != EVP_DecryptFinal_ex(buffer.ctx, buf + evp_len, &evp_len)) return buffer._handle_err();
	result_len += evp_len;

	buffer.padding(result_len);

	*result_buf = buffer.pop();
	return result_len;
}
}}//namespace
