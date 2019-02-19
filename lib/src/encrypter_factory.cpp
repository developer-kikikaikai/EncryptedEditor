/**
 * @file encrypter_factory.c
 * @brief Implement of encrypter_factory.h
 *
 **/
#include <stdlib.h>
#include <map>
#include "encrypter_factory.hpp"

static std::map<enc_api_encrypt_type_e, encapi::EncrypterFactory *> factory_map;

namespace encapi {

EncrypterFactory* get_factory(enc_api_encrypt_type_e type) {
	auto factory = factory_map.find(type);
	if ( factory != factory_map.end() ) {
		return factory->second;
	} else {
		return NULL;
	}
}

void regist_encrypter(enc_api_encrypt_type_e type, EncrypterFactory * factory) {
	factory_map[type] = factory;
}
}
