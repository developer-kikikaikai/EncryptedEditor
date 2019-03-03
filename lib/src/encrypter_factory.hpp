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
	int (*encrypt)(const unsigned char *src_buf, int src_len, unsigned char **result_buf);
	int (*decrypt)(const unsigned char *src_buf, int src_len, unsigned char **result_buf);
};

struct EncrypterFactory{
	EncrypterIF * (*create_if)(void);
	void (*delete_if)(EncrypterIF *);
};
EncrypterFactory* get_factory(enc_api_encrypt_type_e type);
void regist_encrypter(enc_api_encrypt_type_e type, EncrypterFactory * factory);
}
#endif/*ENCDYPTER_FACTORY_H_*/
