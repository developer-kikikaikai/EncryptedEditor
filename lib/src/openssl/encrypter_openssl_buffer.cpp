#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include "encrypter_factory.hpp"
#include "encrypter_openssl_buffer.hpp"
#include <stdio.h>

namespace encapi{namespace openssl {
EncrypterBuffer::EncrypterBuffer(Allocater * allocater) {
	ctx = EVP_CIPHER_CTX_new();
	assert(ctx != NULL);
	_allocater = allocater;
	_buf=NULL;
	_len=0;
};

EncrypterBuffer::~EncrypterBuffer() {
	free(_buf);
	EVP_CIPHER_CTX_free(ctx);
}

int EncrypterBuffer::_handle_err() {
	ERR_print_errors_fp(stderr);
	return -1;
}

void EncrypterBuffer::padding(int result_len) {
	if(_len < result_len) return;
	memset(_buf + result_len, 0, _len - result_len);
}

void EncrypterBuffer::allocate(int src_len) {
	_len = _allocater->allocate(src_len, &_buf);
	assert(_len != 0 && _buf != NULL);
}
unsigned char * EncrypterBuffer::get() {
	return _buf;
};
int EncrypterBuffer::get_len() {
	return _len;
};
unsigned char * EncrypterBuffer::pop() {
	unsigned char * ret_buf = _buf;
	_buf=NULL;
	return ret_buf;
};
}}//namespace
