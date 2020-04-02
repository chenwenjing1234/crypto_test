#ifndef __CRYPT_ECDSA_H
#define __CRYPT_ECDSA_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

int qinn_ecdsa_sign(EC_KEY *eckey, EVP_MD *md, unsigned char *msg, int inlen, 
	unsigned char *sigr, int *rlen, unsigned char *sigs, int *slen);

int qinn_ecdsa_verify(EC_KEY *eckey, EVP_MD *md, unsigned char *msg, int inlen,
	unsigned char *sigr, int rlen, unsigned char *sigs, int slen);

#endif