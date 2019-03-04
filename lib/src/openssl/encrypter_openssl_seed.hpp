/**
 *  * @file encrypter_seed.hpp
 *   * @brief This is API to encrypt/decrypt datas
 *   **/
#ifndef ENCDYPTER_OPENSSL_SEED_H_
#define ENCDYPTER_OPENSSL_SEED_H_

namespace encapi::openssl {
const unsigned char * get_base_key(unsigned char *seed, int length);
const unsigned char * get_base_iv(unsigned char *seed, int length);
}
#endif/*ENCDYPTER_OPENSSL_SEED_H_*/
