#include "crypt_rsa.h"
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>

int qinn_rsa_gen_key(int bits, qinn_rsa_st *rsakey) {
	int ret;
	int b = bits / 2;
	BIGNUM *p = NULL, *q = NULL, *e = NULL, *n = NULL, *d = NULL;
	BIGNUM *psub1 = NULL, *qsub1 = NULL, *one = NULL;
	BIGNUM *phin = NULL, *gcd = NULL;
	BN_CTX *ctx = NULL;

	p = BN_new();
	q = BN_new();
	e = BN_new();
	n = BN_new();
	d = BN_new();
	psub1 = BN_new();
	qsub1 = BN_new();
	one = BN_new();
	phin = BN_new();
	gcd = BN_new();
	ctx = BN_CTX_new();

	BN_set_word(e, 65537);

	for (;;) {
		ret = BN_generate_prime_ex(p, b, 0, NULL, NULL, NULL);
		if (ret != 1) {
			return ret;
		}

		ret = BN_generate_prime_ex(q, b, 0, NULL, NULL, NULL);
		if (ret != 1) {
			return ret;
		}

		BN_one(one);
		BN_sub(psub1, p, one);
		BN_sub(qsub1, q, one);

		ret = BN_mul(phin, psub1, qsub1, ctx);
		if (ret != 1) {
			return ret;
		}

		ret = BN_gcd(gcd, e, phin, ctx);
		if (ret != 1) {
			return ret;
		}

		if (BN_cmp(gcd, one) != 0) {
			continue;
		}

		BN_mod_inverse(d, e, phin, ctx);

		break;
	}

	ret = BN_mul(n, p, q, ctx);
	if (ret != 1) {
		return ret;
	}

	rsakey->bits = bits;
	rsakey->n = n;
	rsakey->e = e;
	rsakey->d = d;
	return 0;
}

int qinn_rsa_enc(qinn_rsa_st *rsakey, unsigned char *msg, int inlen,
	unsigned char *out, int *outlen) {
	int ret = 1, padding_len;
	BIGNUM *m = NULL, *c = NULL;
	BN_CTX *ctx = NULL;
	unsigned char *buf = NULL;
	int bytes = rsakey->bits / 8;
	unsigned char *p = NULL;
	BIGNUM *test = NULL;
	unsigned char testbuf[128] = { 0 };
	int testbuf_len;

	if (inlen > bytes - 11) {
		return ret;
	}

	padding_len = bytes - 3 - inlen;
	buf = (unsigned char *)calloc(bytes, 1);

	buf[0] = 0;
	buf[1] = 2;

	p = buf + 2;
	RAND_bytes(p, padding_len);

	
	for (int i = 0; i < padding_len; i++) {
		if (*p == 0) {
			do {
				RAND_bytes(p, 1);
			} while (*p == 0);
		}
		p++;
	}

	buf[padding_len + 2] = 0;

	memcpy(buf + padding_len + 3, msg, inlen);

	m = BN_new();
	c = BN_new();
	ctx = BN_CTX_new();


	printf("input data:\n");
	for (int i = 0; i < bytes; i++) {
		printf("%02X", buf[i]);
	}
	printf("\n");

	BN_bin2bn(buf, bytes, m);

	ret = BN_mod_exp(c, m, rsakey->e, rsakey->n, ctx);
	if (ret != 1) {
		return ret;
	}

	test = BN_new();
	ret = BN_mod_exp(test, c, rsakey->d, rsakey->n, ctx);
	if (ret != 1) {
		return ret;
	}
	testbuf_len = BN_bn2bin(test, testbuf);
	printf("dec result:\n");
	for (int i = 0; i < testbuf_len; i++) {
		printf("%02X", testbuf[i]);
	}
	printf("\n");


	*outlen = BN_bn2bin(c, out);

	printf("enc result:\n");
	for (int i = 0; i < *outlen; i++) {
		printf("%02X", out[i]);
	}
	printf("\n");

	return 0;
}

int qinn_rsa_dec(qinn_rsa_st *rsakey, unsigned char *cipher, int inlen,
	unsigned char *out, int *outlen) {
	int ret;
	BIGNUM *c = NULL, *m = NULL;
	BN_CTX *ctx = NULL;
	int bytes = rsakey->bits / 8;
	unsigned char *buf = NULL;
	unsigned char *p = NULL;
	int buflen;
	unsigned char test[128] = { 0 };

	c = BN_new();
	m = BN_new();
	ctx = BN_CTX_new();
	buf = (unsigned char*)calloc(bytes, 1);
	p = buf;

	printf("dec input 1:\n");
	for (int i = 0; i < inlen; i++) {
		printf("%02X", cipher[i]);
	}
	printf("\n");

	BN_bin2bn(cipher, inlen, c);

	BN_bn2bin(c, test);
	printf("dec input 2:\n");
	for (int i = 0; i < BN_num_bytes(c); i++) {
		printf("%02X", test[i]);
	}
	printf("\n");

	ret = BN_mod_exp(m, c, rsakey->d, rsakey->n, ctx);
	if (ret != 1) {
		return ret;
	}

	buflen = BN_bn2bin(m, buf+1);

	if (*p++ != 0 || *p++ != 2) {
		return 1;
	}

	for (int i = 2; i < bytes - 2; i++) {
		if (*p++ == 0) {
			break;
		}
	}

	*outlen = bytes - (p - buf);
	memcpy(out, p, *outlen);
	return 0;
}