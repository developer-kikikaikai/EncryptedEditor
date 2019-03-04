/**
 *  * @file encrypt_openssl.h
 *   * @brief This is API to encrypt/decrypt datas
 *   **/
#ifndef ENCDYPTER_OPENSSL_H_
#define ENCDYPTER_OPENSSL_H_
#include <openssl/evp.h>
#include "encrypter_factory.hpp"
#include "encrypter_openssl_buffer.hpp"

namespace encapi::openssl {
/* @brief encrypter base struct*/
class EncrypterOpenssl : public EncrypterIF {
private:
	/*get parameter to */
	virtual const unsigned char * _get_key(unsigned char *seed, int len) = 0;
	virtual const unsigned char * _get_iv(unsigned char *seed, int len) = 0;
	virtual const EVP_CIPHER * _get_evp_cipher() = 0;
	void get_salt(unsigned char *salt);
public:
	Allocater *enc_allocater;
	Allocater *dec_allocater;
	int encrypt(const unsigned char *src_buf, int src_len, unsigned char **result_buf);
	int decrypt(const unsigned char *src_buf, int src_len, unsigned char **result_buf);
};
}
#endif/*ENCDYPTER_OPENSSL_H_*/
