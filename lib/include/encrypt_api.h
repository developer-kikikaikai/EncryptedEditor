/**
 *  * @file encrypt_api.h
 *   * @brief This is API to encrypt/decrypt datas
 *   **/
#ifndef ENCDYPT_API_H_
#define ENCDYPT_API_H_
#ifdef __cplusplus
extern "C" {
#endif  /*! __cplusplus */
typedef enum {
	ENC_API_ENCRYPT_TYPE_AES256_CBC,
	ENC_API_ENCRYPT_TYPE_ARIA128_CBC,
	ENC_API_ENCRYPT_TYPE_CAMELLIA256_CBC,
	ENC_API_ENCRYPT_TYPE_CHACHA20,
	ENC_API_ENCRYPT_TYPE_CHACHA20_POLY1305,
} enc_api_encrypt_type_e;
/**
 * @brief encrypt
 * @param[in] type encryption type
 * @param[in] src_buf source buffer
 * @param[in] src_len source length
 * @param[out] result_buf encrypted data buffer
 * @return encrypted data length. error if return negative value
 * @note please release result_buf by using free
 */
int enc_api_encrypt(enc_api_encrypt_type_e type, const unsigned char *src_buf, int src_len, unsigned char ** result_buf);
/**
 * @brief decrypt
 * @param[in] type encryption type
 * @param[in] src_buf source buffer
 * @param[in] src_len source length
 * @param[out] result_buf encrypted data buffer
 * @return encrypted data length. error if return negative value
 * @note please release result_buf by using free
 */
int enc_api_decrypt(enc_api_encrypt_type_e type, const unsigned char *src_buf, int src_len, unsigned char ** result_buf);
#ifdef __cplusplus
}
#endif  /*! __cplusplus */
#endif/*ENCDYPT_API_H_*/
