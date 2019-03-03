#include <string.h>
#include <openssl/evp.h>
#include "encrypter_seed.hpp"
#include "encrypter_openssl_seed.hpp"
#include <stdio.h>
#include <stdlib.h>

namespace encapi::openssl {
static void base64_encode(const unsigned char* src_buf, size_t src_len, unsigned char** result) {
	EVP_EncodeBlock(*result, src_buf, src_len);
}
const unsigned char * get_base_key(void) {
	unsigned char local_key_data[]="\
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\
XGOzVsARyZUc0TjFVA0P9UyaxEkzNQ==\
";
	static unsigned char *local_private_key=NULL;
	if(local_private_key != NULL) {
		return local_private_key;
	}

	const unsigned char *seed = get_seed();
	int len=strlen((const char *)seed), i=0;
	for(i=0;i<len; i++) {
		local_key_data[i] = local_key_data[i] ^ seed[i];
	}
	local_private_key = (unsigned char *)calloc(1, len * 4/3);
	base64_encode(local_key_data, len, &local_private_key);
        return local_private_key;
}

#define ENCDYPTER_OPENSSL_IV (16)
#define ENCDYPTER_OPENSSL_IV_BEFORE_ENCODE (9)
const unsigned char * get_base_iv(void) {
	static unsigned char local_iv_data[ENCDYPTER_OPENSSL_IV]={0};
	if(local_iv_data[0] != 0) {
		return local_iv_data;
	}

	const unsigned char *seed=get_base_key();
	unsigned char local_tmp_iv_data[ENCDYPTER_OPENSSL_IV_BEFORE_ENCODE]={0};
	int block_len=strlen((const char *)seed)/ENCDYPTER_OPENSSL_IV_BEFORE_ENCODE, i=0;
	int block_index=0;
	for(block_index=0;block_index<block_len;block_index++) {
		for(i=0;i<ENCDYPTER_OPENSSL_IV_BEFORE_ENCODE;i++) {
			local_tmp_iv_data[i] = local_tmp_iv_data[i] ^ seed[ (ENCDYPTER_OPENSSL_IV_BEFORE_ENCODE * block_index) + i];
		}
	}
	unsigned char *buf = local_iv_data;
	base64_encode(local_tmp_iv_data, sizeof(local_tmp_iv_data), &buf);
	return local_iv_data;
}

}
