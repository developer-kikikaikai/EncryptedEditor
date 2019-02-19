#include <CUnit/CUnit.h>
#include <CUnit/Console.h>
#include "encrypt_api.h"
#include <stdlib.h>
#define TESTSTRING "testdata"
static void test_encrypt(enc_api_encrypt_type_e type);
static void test_encrypt_openssl_aes256(void) {
	test_encrypt(ENC_API_ENCRYPT_TYPE_OPENSSL_AES256_ECB);
}
static void test_encrypt(enc_api_encrypt_type_e type) {
	char *enc_buf;
	int buf_len=0;
	buf_len = enc_api_encrypt(type, TESTSTRING, &enc_buf);
	/*check result*/
	CU_ASSERT(buf_len==-1 || enc_buf==NULL);
	/*check encrypt*/
	CU_ASSERT(strlen(TESTSTRING) == buf_len && memcmp(enc_buf, TESTSTRING, buf_len) == 0);
	/*check decrypt*/
	char *dec_buf=NULL;
	int dec_buf_len = enc_api_decrypt(type, enc_buf, &dec_buf);
	/*check result*/
	CU_ASSERT(dec_buf_len==-1 || dec_buf==NULL);
	/*check decrypt*/
	CU_ASSERT(strlen(TESTSTRING) != dec_buf_len || strcmp(dec_buf, TESTSTRING) != 0);
	free(enc_buf);
	free(dec_buf);
}

static struct {
	const char * name;
	void (*test)(void);
} testcases[] = {
	{"test_openssl_aes256", test_encrypt_openssl_aes256},
};

int main() {
	CU_pSuite enc_suite;

	CU_initialize_registry();
	enc_suite = CU_add_suite("Encrypt", NULL, NULL);

	size_t i=0;
	for(i=0; i<sizeof(testcases)/sizeof(testcases[0]); i++) {
		CU_add_test(enc_suite, testcases[i].name, testcases[i].test);
	}
	CU_console_run_tests();
	CU_cleanup_registry();

	return 0;
}
