#ifndef __CRYPT_RSA_H
#define __CRYPT_RSA_H

#include <openssl/bn.h>

typedef struct _qinn_rsa_st {
	BIGNUM *n;
	BIGNUM *e;
	BIGNUM *d;
	int bits;
} qinn_rsa_st;


int qinn_rsa_gen_key(int bits, qinn_rsa_st *rsakey);

int qinn_rsa_enc(qinn_rsa_st *rsakey, unsigned char *msg, int inlen, 
	unsigned char *out, int *outlen);

int qinn_rsa_dec(qinn_rsa_st *rsakey, unsigned char *cipher, int inlen,
	unsigned char *out, int *outlen);

#endif