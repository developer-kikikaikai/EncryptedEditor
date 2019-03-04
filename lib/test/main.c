#include <CUnit/CUnit.h>
#include <CUnit/Console.h>
#include "encrypt_api.h"
#include <stdlib.h>
#include <stdio.h>
#define TESTSTRING "testdata"
#define TESTBINARY_LEN (50)
static unsigned char test_binary[TESTBINARY_LEN];
#define TESTBINARY test_binary
#define TEST_MULTITIME (50)
#define TEST_LARGEDATA_LEN (8192)

__attribute__((constructor))
static void test_initialize() {
	int i=0;
	for(i=0;i<TESTBINARY_LEN;i++) {
		test_binary[i]=i;
	}
}

static void test_encrypt(enc_api_encrypt_type_e type);
static void test_encrypt_multitimes(enc_api_encrypt_type_e type);
static void test_encrypt_uniq_encode(enc_api_encrypt_type_e type);
static void test_encrypt_binary(enc_api_encrypt_type_e type);
static void test_encrypt_zero(enc_api_encrypt_type_e type);
static void test_encrypt_largedata(enc_api_encrypt_type_e type);
static void test_encrypt_all(enc_api_encrypt_type_e type);

static void test_encrypt_aes256(void) {
	test_encrypt_all(ENC_API_ENCRYPT_TYPE_AES256_CBC);
}
static void test_encrypt_aria128(void) {
	test_encrypt_all(ENC_API_ENCRYPT_TYPE_ARIA128_CBC);
}
static void test_encrypt_camellia256(void) {
	test_encrypt_all(ENC_API_ENCRYPT_TYPE_CAMELLIA256_CBC);
}
static void test_encrypt_chacha20(void) {
	test_encrypt_all(ENC_API_ENCRYPT_TYPE_CHACHA20);
}
static void test_encrypt_chacha20_poly1305(void) {
	test_encrypt_all(ENC_API_ENCRYPT_TYPE_CHACHA20_POLY1305);
}

static void test_encrypt_all(enc_api_encrypt_type_e type) {
	test_encrypt(type);
	test_encrypt_binary(type);
	test_encrypt_zero(type);
	test_encrypt_multitimes(type);
	test_encrypt_uniq_encode(type);
	test_encrypt_largedata(type);
}

static void test_encrypt(enc_api_encrypt_type_e type) {
	unsigned char *enc_buf=NULL;
	int buf_len=0;
	buf_len = enc_api_encrypt(type, (const unsigned char *)TESTSTRING, strlen(TESTSTRING), &enc_buf);
	/*check result*/
       	CU_ASSERT_FATAL(0 < buf_len && enc_buf!=NULL);
	/*check encrypt*/
	CU_ASSERT(strlen(TESTSTRING) != buf_len || memcmp(enc_buf, TESTSTRING, buf_len) != 0);
	/*check decrypt*/
	unsigned char *dec_buf=NULL;
	int dec_buf_len = enc_api_decrypt(type, (const unsigned char *)enc_buf, buf_len, &dec_buf);
	/*check result*/
	CU_ASSERT_FATAL(0 < dec_buf_len && dec_buf!=NULL);
	/*check decrypt*/
	CU_ASSERT(strlen(TESTSTRING) == dec_buf_len && strcmp((const char *)dec_buf, TESTSTRING) == 0);
	free(enc_buf);
	free(dec_buf);
}

static void test_encrypt_binary(enc_api_encrypt_type_e type) {
	unsigned char *enc_buf=NULL;
	int buf_len=0;
	buf_len = enc_api_encrypt(type, TESTBINARY, TESTBINARY_LEN, &enc_buf);
	/*check result*/
       	CU_ASSERT_FATAL(0 < buf_len && enc_buf!=NULL);
	/*check encrypt*/
	CU_ASSERT(TESTBINARY_LEN != buf_len || memcmp(enc_buf, TESTBINARY, buf_len) != 0);
	/*check decrypt*/
	unsigned char *dec_buf=NULL;
	int dec_buf_len = enc_api_decrypt(type, enc_buf, buf_len, &dec_buf);
	/*check result*/
	CU_ASSERT_FATAL(0 < dec_buf_len && dec_buf!=NULL);
	/*check decrypt*/
	CU_ASSERT(TESTBINARY_LEN == dec_buf_len && memcmp(dec_buf, TESTBINARY, buf_len) == 0);
	/*check decrypt*/
	free(enc_buf);
	free(dec_buf);
}

static void test_encrypt_zero(enc_api_encrypt_type_e type) {
	unsigned char *buf=NULL;
	int buf_len=0;
	buf_len = enc_api_encrypt(type, 0, 0, &buf);
	CU_ASSERT_FATAL(buf_len <= 0 && buf==NULL);
	buf_len = enc_api_decrypt(type, 0, 0, &buf);
	CU_ASSERT_FATAL(buf_len <= 0 && buf==NULL);
}

static void test_encrypt_multitimes(enc_api_encrypt_type_e type) {
	unsigned char first_string[]=TESTSTRING;
	unsigned char **enc_bufs=calloc(TEST_MULTITIME+1, sizeof(unsigned char *));
	int *buf_lens=calloc(TEST_MULTITIME+1, sizeof(int));
	enc_bufs[0]=first_string;
	buf_lens[0]=strlen(TESTSTRING);
	int i=0;
	for(i=0;i<TEST_MULTITIME;i++) {
		buf_lens[i+1] = enc_api_encrypt(type, enc_bufs[i], buf_lens[i], &enc_bufs[i+1]);
		/*check result*/
       		CU_ASSERT_FATAL(0 < buf_lens[i+1] && enc_bufs[i+1]!=NULL);
		/*check encrypt*/
		CU_ASSERT(TESTBINARY_LEN != buf_lens[i+1] || memcmp(enc_bufs[i+1], enc_bufs[i], buf_lens[i+1]) != 0);
	}
	/*check decrypt*/
	unsigned char **dec_bufs=calloc(TEST_MULTITIME, sizeof(unsigned char *));
	int *dec_buf_lens=calloc(TEST_MULTITIME, sizeof(int));
	for(i=TEST_MULTITIME-1;0<i;i--) {
		dec_buf_lens[i] = enc_api_decrypt(type, enc_bufs[i+1], buf_lens[i+1], &dec_bufs[i]);
		/*check result*/
		CU_ASSERT_FATAL(0 < dec_buf_lens[i] && dec_bufs[i]!=NULL);
		CU_ASSERT(buf_lens[i] == dec_buf_lens[i] && memcmp(dec_bufs[i], enc_bufs[i], dec_buf_lens[i]) == 0);
		free(enc_bufs[i+1]);
		free(dec_bufs[i]);
	}
	free(enc_bufs);
	free(buf_lens);
}

static void test_encrypt_uniq_encode(enc_api_encrypt_type_e type) {
	unsigned char first_string[]=TESTSTRING;
	unsigned char **enc_bufs=calloc(TEST_MULTITIME+1, sizeof(unsigned char *));
	int *buf_lens=calloc(TEST_MULTITIME+1, sizeof(int));
	enc_bufs[0]=first_string;
	buf_lens[0]=strlen(TESTSTRING);
	int i=0;
	for(i=0;i<TEST_MULTITIME;i++) {
		buf_lens[i+1] = enc_api_encrypt(type, enc_bufs[i], buf_lens[i], &enc_bufs[i+1]);
		/*check result*/
       		CU_ASSERT_FATAL(0 < buf_lens[i+1] && enc_bufs[i+1]!=NULL);
		/*check encrypt*/
		CU_ASSERT(TESTBINARY_LEN != buf_lens[i+1] || memcmp(enc_bufs[i+1], enc_bufs[i], buf_lens[i+1]) != 0);
	}
	int j=0;
	for(i=TEST_MULTITIME-1;i<1;i--) {
		for(j=i-1;j<0;j--) {
			CU_ASSERT(buf_lens[i] != buf_lens[j] || memcmp(enc_bufs[i], enc_bufs[j], buf_lens[j]) != 0);
		}
		free(enc_bufs[i]);
	}
	free(enc_bufs);
	free(buf_lens);
}

static void test_encrypt_largedata(enc_api_encrypt_type_e type) {
	unsigned char *base_buf=calloc(1, TEST_LARGEDATA_LEN);
	int i=0;
	for(i=0;i<TEST_LARGEDATA_LEN;i++) {
		base_buf[i]=i;
	}
	unsigned char *enc_buf=NULL;
	int buf_len=0;
	buf_len = enc_api_encrypt(type, base_buf, TEST_LARGEDATA_LEN, &enc_buf);
	/*check result*/
       	CU_ASSERT_FATAL(0 < buf_len && enc_buf!=NULL);
	/*check encrypt*/
	CU_ASSERT(TEST_LARGEDATA_LEN != buf_len || memcmp(enc_buf, base_buf, TEST_LARGEDATA_LEN) != 0);
	/*check decrypt*/
	unsigned char *dec_buf=NULL;
	int dec_buf_len = enc_api_decrypt(type, enc_buf, buf_len, &dec_buf);
	/*check result*/
	CU_ASSERT_FATAL(0 < dec_buf_len && dec_buf!=NULL);
	/*check decrypt*/
	CU_ASSERT(TEST_LARGEDATA_LEN == dec_buf_len && memcmp(dec_buf, base_buf, TEST_LARGEDATA_LEN) == 0);
	free(enc_buf);
	free(dec_buf);
	free(base_buf);
}

static struct {
	const char * name;
	void (*test)(void);
} testcases[] = {
	{"test_aes256", test_encrypt_aes256},
	{"test_aria128", test_encrypt_aria128},
	{"test_camellia256", test_encrypt_camellia256},
	{"test_chacha20", test_encrypt_chacha20},
	{"test_chacha20_poly1305", test_encrypt_chacha20_poly1305},
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
