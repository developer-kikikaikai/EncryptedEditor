#include <CUnit/CUnit.h>
#include <CUnit/Console.h>
#include "encrypt_api.h"
#include <stdlib.h>
#include <stdio.h>
#define TESTSTRING "testdata"
static void test_encrypt(enc_api_encrypt_type_e type);
static void test_encrypt_openssl_aes256(void) {
	test_encrypt(ENC_API_ENCRYPT_TYPE_OPENSSL_AES256_ECB);
}
static void test_encrypt(enc_api_encrypt_type_e type) {
	unsigned char *enc_buf=NULL;
	int buf_len=0;
	buf_len = enc_api_encrypt(type, (const unsigned char *)TESTSTRING, strlen(TESTSTRING), &enc_buf);
	/*check result*/
	CU_ASSERT(buf_len!=-1 && enc_buf!=NULL);
	/*check encrypt*/
	CU_ASSERT(strlen(TESTSTRING) != buf_len && memcmp(enc_buf, TESTSTRING, buf_len) != 0);
	/*check decrypt*/
	unsigned char *dec_buf=NULL;
	int dec_buf_len = enc_api_decrypt(type, (const unsigned char *)enc_buf, buf_len, &dec_buf);
	/*check result*/
	CU_ASSERT(dec_buf_len!=-1 && dec_buf!=NULL);
	/*check decrypt*/
	if(strlen(TESTSTRING) == dec_buf_len) fprintf(stderr, "strlen(TESTSTRING) %d == dec_buf_len %d\n", strlen(TESTSTRING), dec_buf_len);
	if(strcmp(dec_buf, TESTSTRING) == 0) fprintf(stderr, "%s\n", dec_buf);
	fprintf(stderr, "%s\n", dec_buf);
	fprintf(stderr, "%s %d\n", TESTSTRING, strcmp(dec_buf, TESTSTRING));
	int i=0;
	for(i=0;i<strlen(TESTSTRING)+1;i++) {
		fprintf(stderr, "%2x ", dec_buf[i]);
	}
	fprintf(stderr, "\n");
	CU_ASSERT(strlen(TESTSTRING) == dec_buf_len && strcmp((const char *)dec_buf, TESTSTRING) == 0);
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
