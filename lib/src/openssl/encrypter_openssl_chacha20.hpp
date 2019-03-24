/**
 *  * @file encrypter_openssl_chacha20.hpp
 *   * @brief This is API to encrypt/decrypt datas
 *   **/
#ifndef ENCDYPTER_OPENSSL_CHACHA20_H_
#define ENCDYPTER_OPENSSL_CHACHA20_H_
#include "encrypter_factory.hpp"

namespace encapi{namespace openssl {
class CHACHA20Factory: public EncrypterFactory {
public:
	EncrypterIF * create_if(void);
	void delete_if(EncrypterIF *);
};
}}//namespace
#endif/*ENCDYPTER_OPENSSL_CHACHA20_H_*/
