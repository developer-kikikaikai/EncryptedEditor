#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <time.h>
#include "encrypter_factory.hpp"
#include "encrypter_openssl.hpp"

#define ENC_OPENSSL_SALT_TAG "Salted_libcrypto_"
#define ENC_OPENSSL_SALT_TAG_LEN strlen(ENC_OPENSSL_SALT_TAG)
#define ENC_OPENSSL_SALT_LEN (8 + ENC_OPENSSL_SALT_TAG_LEN + 1)
namespace encapi::openssl {

void EncrypterOpenssl::get_salt(unsigned char *salt) {
	struct timespec timedata;
	clock_gettime(CLOCK_REALTIME, &timedata);
	struct drand48_data buffer;
	srand48_r(timedata.tv_nsec, &buffer);
	long int result;
	lrand48_r(&buffer, &result);

	snprintf((char *)salt, ENC_OPENSSL_SALT_LEN , "%s%08x", ENC_OPENSSL_SALT_TAG, (unsigned int)result);
}

int EncrypterOpenssl::encrypt(const unsigned char *src_buf, int src_len, unsigned char **result_buf) {
	/*encrypting as https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption*/

	/*fail safe*/
	if(src_len == 0 || src_buf == NULL) return -1;

	/*initialize EVP_CIPHER_CTX*/
	EncrypterBuffer buffer(enc_allocater);

	buffer.allocate(src_len + ENC_OPENSSL_SALT_LEN);

	unsigned char salt[ENC_OPENSSL_SALT_LEN + 1];
	get_salt(salt);

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

	buffer.allocate(src_len);

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
}
