/**
 *  * @file encrypt_api.h
 *   * @brief This is API to encrypt/decrypt datas
 *   **/
#ifndef ENCDYPTER_FACTORY_H_
#define ENCDYPTER_FACTORY_H_
#include "encrypt_api.h"
namespace encapi {
/* @brief encrypter interface */
struct EncrypterIF{
	virtual int encrypt(const unsigned char *src_buf, int src_len, unsigned char **result_buf) = 0;
	virtual int decrypt(const unsigned char *src_buf, int src_len, unsigned char **result_buf) = 0;
	virtual ~EncrypterIF() {}
};

struct EncrypterFactory{
	virtual EncrypterIF * create_if(void) = 0;
	virtual void delete_if(EncrypterIF *) = 0;
	virtual ~EncrypterFactory() {}
};
EncrypterFactory* get_factory(enc_api_encrypt_type_e type);
}
#endif/*ENCDYPTER_FACTORY_H_*/
