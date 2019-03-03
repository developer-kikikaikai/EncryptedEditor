#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include "encrypter_factory.hpp"
#include "encrypter_openssl.hpp"

namespace encapi::openssl {

int EncrypterOpenssl::encrypt(const unsigned char *src_buf, int src_len, unsigned char **result_buf) {
	/*encrypting as https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption*/

	/*initialize EVP_CIPHER_CTX*/
	EncrypterBuffer buffer(enc_allocater);

	if(1 != EVP_EncryptInit_ex(buffer.ctx, _get_evp_cipher(), NULL, _get_key(), _get_iv())) return buffer._handle_err();

	buffer.allocate(src_len);

	unsigned char * buf = buffer.get();
	int result_len=0;
	int evp_len=0;
	if(1 != EVP_EncryptUpdate(buffer.ctx, buf, &evp_len, src_buf, src_len) ) return buffer._handle_err();
	result_len = evp_len;

	if(1 != EVP_EncryptFinal_ex(buffer.ctx, buf + evp_len, &evp_len)) return buffer._handle_err();
	result_len += evp_len;

	buffer.padding(result_len);

	*result_buf = buffer.pop();
	return result_len;
}

int EncrypterOpenssl::decrypt(const unsigned char *src_buf, int src_len, unsigned char **result_buf) {
	/*decrypting as https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption*/

	/*initialize EVP_CIPHER_CTX*/
	EncrypterBuffer buffer(dec_allocater);

	if(1 != EVP_DecryptInit_ex(buffer.ctx, _get_evp_cipher(), NULL, _get_key(), _get_iv())) return buffer._handle_err();

	buffer.allocate(src_len);

	unsigned char * buf = buffer.get();
	int result_len=0;
	int evp_len=0;
	if(1 != EVP_DecryptUpdate(buffer.ctx, buf, &evp_len, src_buf, src_len) ) return buffer._handle_err();
	result_len = evp_len;

	if(1 != EVP_DecryptFinal_ex(buffer.ctx, buf + evp_len, &evp_len)) return buffer._handle_err();
	result_len += evp_len;

	buffer.padding(result_len);

	*result_buf = buffer.pop();
	return result_len;
}
}
