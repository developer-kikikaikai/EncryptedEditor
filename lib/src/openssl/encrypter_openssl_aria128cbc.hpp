/**
 *  * @file encrypter_openssl_aria128cbc.hpp
 *   * @brief This is API to encrypt/decrypt datas
 *   **/
#ifndef ENCDYPTER_OPENSSL_ARIA128CBC_H_
#define ENCDYPTER_OPENSSL_ARIA128CBC_H_
#include "encrypter_factory.hpp"

namespace encapi::openssl {
class ARIA128CBCFactory: public EncrypterFactory {
public:
	EncrypterIF * create_if(void);
	void delete_if(EncrypterIF *);
};
}
#endif/*ENCDYPTER_OPENSSL_ARIA128CBC_H_*/
