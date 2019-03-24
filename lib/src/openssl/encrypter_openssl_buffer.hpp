/**
 *  * @file encrypt_openssl_buffer.h
 *   * @brief This is API to encrypt/decrypt datas buffer
 *   **/
#ifndef ENCDYPTER_OPENSSL_BUFFER_H_
#define ENCDYPTER_OPENSSL_BUFFER_H_
#include <openssl/evp.h>
#include <assert.h>
#include "encrypter_openssl_buffer.hpp"

namespace encapi{namespace openssl {
/*buffer allocater. buffer size is related to algorithm, so you have to define it into method*/
struct Allocater {
	virtual int allocate(int src_len, unsigned char ** result_buf) = 0;
};

class BaseAllocater : public Allocater {
private:
	int _padding_len;
public:
	BaseAllocater(int len) {
		_padding_len = len;
	}
	int allocate(int src_len, unsigned char ** result_buf) {
		unsigned char *buf = (unsigned char *)calloc(1, src_len + _padding_len + 1);
		if(buf == NULL) return 0;
		*result_buf = buf;
		return src_len;
	}
};

class EncrypterBuffer {
private:
	unsigned char * _buf;
	int _len;
	Allocater *_allocater;
public:
	EVP_CIPHER_CTX * ctx;
	EncrypterBuffer(Allocater * allocater);
	~EncrypterBuffer();
	int _handle_err();
	void padding(int len);
	void allocate(int src_len);
	unsigned char * get();
	int get_len();
	unsigned char * pop();
};

}}//namespace
#endif/*ENCDYPTER_OPENSSL_BUFFER_H_*/
