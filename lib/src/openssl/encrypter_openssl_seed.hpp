/**
 *  * @file encrypter_seed.hpp
 *   * @brief This is API to encrypt/decrypt datas
 *   **/
#ifndef ENCDYPTER_OPENSSL_SEED_H_
#define ENCDYPTER_OPENSSL_SEED_H_

namespace encapi::openssl {
const unsigned char * get_base_key(void);
const unsigned char * get_base_iv(void);
}
#endif/*ENCDYPTER_OPENSSL_SEED_H_*/
