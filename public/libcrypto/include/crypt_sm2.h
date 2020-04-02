#ifndef __CRYPT_SM2_H
#define __CRYPT_SM2_H

#include <openssl/ec.h>

#define SM2_PRIKEY_LEN			(32)
#define SM2_PUBKEY_LEN			(65)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _sm2_key_st {
	unsigned char prikey[SM2_PRIKEY_LEN];
	unsigned char pubkey[SM2_PUBKEY_LEN];
	EC_GROUP *sm2group;
	EC_POINT *sm2ptpubkey;
	BIGNUM *sm2bnprikey;
} sm2_key_st;

int qinn_sm2_gen_keypair(sm2_key_st *sm2key);

int qinn_sm2_enc(sm2_key_st *sm2key, unsigned char *msg, int msglen,
	unsigned char *cipher, int *cipher_len);

int qinn_sm2_dec(sm2_key_st *sm2key, unsigned char *cipher, int cipher_len,
	unsigned char *plain, int *plain_len);

int qinn_sm2_sign(sm2_key_st *sm2key, unsigned char *msg, int msglen,
	unsigned char *sigr, unsigned char *sigs);

int qinn_sm2_verify(sm2_key_st *sm2key, unsigned char *msg, int msglen,
	unsigned char *sigr, unsigned char *sigs);

int crypt_test();

#ifdef __cplusplus
}
#endif

#endif  /* __CRYPT_SM2_H */
