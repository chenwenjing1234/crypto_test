#ifndef __CRYPT_AES_H__
#define __CRYPT_AES_H__

#define AES_DECRYPT 0
#define AES_ENCRYPT 1

#ifdef __cplusplus
extern "C" {
#endif

struct aes_s
{
	int nr;					/* number of rounds */
	unsigned long *rk;		/* AES round keys */
	unsigned long buf[68];	/* unaligned data */
};

typedef struct aes_s aes_context;

int aes_setkey_enc(aes_context *ctx, const unsigned char *key, int keysize);
int aes_setkey_dec(aes_context *ctx, const unsigned char *key, int keysize);
void aes_crypt_ecb(aes_context *ctx,
	int mode,
	const unsigned char input[16],
    unsigned char output[16]);

void aes_crypt_ctr(aes_context *ctx,
                   int mode,
                   int length,
                   unsigned char nonce[8],
                   long long offset,
                   const unsigned char *input,
                   unsigned char *output);

#ifdef __cplusplus
}
#endif

#endif /* __CRYPT_AES_H__ */
