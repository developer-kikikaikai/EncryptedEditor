/**
 *  * @file encrypter_openssl_aes256cbc.hpp
 *   * @brief This is API to encrypt/decrypt datas
 *   **/
#ifndef ENCDYPTER_OPENSSL_AES256CBC_H_
#define ENCDYPTER_OPENSSL_AES256CBC_H_
#include "encrypter_factory.hpp"

namespace encapi{namespace openssl {
class AES256CBCFactory: public EncrypterFactory {
public:
	EncrypterIF * create_if(void);
	void delete_if(EncrypterIF *);
};
}}//namespace
#endif/*ENCDYPTER_OPENSSL_AES256CBC_H_*/
