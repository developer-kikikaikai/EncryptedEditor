/**
 *  * @file encrypt_api.h
 *   * @brief This is API to encrypt/decrypt datas
 *   **/
#ifndef ENCDYPTER_FACTORY_H_
#define ENCDYPTER_FACTORY_H_
#include "encrypt_api.h"

typedef struct {
	int (*encrypt)(const char *src_buf, char **result_buf);
	int (*decrypt)(const char *src_buf, char **result_buf);
} *EncrypterIF;

typedef struct {
	EncrypterIF (*create)(void);
	void (*delete)(EncrypterIF instance);
} *EncrypterFactory;

EncrypterFactory enc_api_factory_new(enc_api_encrypt_type_e type);
void enc_api_create_factory_free(EncrypterFactory this);
#endif/*ENCDYPTER_FACTORY_H_*/
