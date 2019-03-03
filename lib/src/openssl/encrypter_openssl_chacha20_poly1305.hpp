/**
 *  * @file encrypter_openssl_chacha20_poly1305.hpp
 *   * @brief This is API to encrypt/decrypt datas
 *   **/
#ifndef ENCDYPTER_OPENSSL_CHACHA20_POLY1305_H_
#define ENCDYPTER_OPENSSL_CHACHA20_POLY1305_H_
#include "encrypter_factory.hpp"

namespace encapi::openssl {
class CHACHA20_POLY1305Factory: public EncrypterFactory {
public:
	EncrypterIF * create_if(void);
	void delete_if(EncrypterIF *);
};
}
#endif/*ENCDYPTER_OPENSSL_CHACHA20_POLY1305_H_*/
