#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include "crypt_sm2.h"

char *sm2_p = "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
char *sm2_a = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
char *sm2_b = "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
char *sm2_gx = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
char *sm2_gy = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";
char *sm2_order = "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";
unsigned long long sm2_cof = 1;
char *sm2id = "1234567812345678";
uint16_t sm2id_len = 16;


static int print_hex(unsigned char *bytes, int len) {
	for (int i = 0; i < len; i++) {
		printf("%02X", bytes[i]);
	}
	printf("\n");
}

int crypt_test() {
	printf("hihihihi\n");
	unsigned char prikey[SM2_PRIKEY_LEN] = { 0 };
	unsigned char pubkey[SM2_PUBKEY_LEN] = { 0 };
	qinn_sm2_gen_keypair(prikey, pubkey);



	return 0;
}

int qinn_sm2_gen_keypair(sm2_key_st *sm2key) {
	BIGNUM *bnpri = NULL;
	EC_GROUP *group = NULL;
	BIGNUM *p = NULL, *a = NULL, *b = NULL, *order = NULL, *pubkeyx = NULL, *pubkeyy = NULL;
	BIGNUM *gx = NULL, *gy = NULL, *cof;
	EC_POINT *ptpubkey = NULL, *ptg = NULL;
	int len;
	int ret;

	BN_hex2bn(&p, sm2_p);
	BN_hex2bn(&a, sm2_a);
	BN_hex2bn(&b, sm2_b);
	BN_hex2bn(&gx, sm2_gx);
	BN_hex2bn(&gy, sm2_gy);
	BN_hex2bn(&order, sm2_order);

	group = EC_GROUP_new_curve_GFp(p, a, b, NULL);

	bnpri = BN_new();
	pubkeyx = BN_new();
	pubkeyy = BN_new();
	cof = BN_new();
	BN_set_word(cof, sm2_cof);

	//must 32 bytes
	BN_rand_range(bnpri, order);
	len = BN_num_bytes(bnpri);


	ptpubkey = EC_POINT_new(group);
	ptg = EC_POINT_new(group);;

	ret = EC_POINT_set_affine_coordinates_GFp(group, ptg, gx, gy, NULL);
	if (ret != 1) {
		return ret;
	}

	ret = EC_GROUP_set_generator(group, ptg, order, cof);
	if (ret != 1) {
		return ret;
	}

	//point must on curl
	ret = EC_POINT_mul(group, ptpubkey, bnpri, NULL, NULL, NULL);
	if (ret != 1) {
		return ret;
	}

	//pubkeyx pubkeyy must 32bytes
	EC_POINT_get_affine_coordinates_GFp(group, ptpubkey, pubkeyx, pubkeyy, NULL);
	len = BN_num_bytes(pubkeyx);
	len = BN_num_bytes(pubkeyy);

	sm2key->pubkey[0] = 0x04;
	BN_bn2bin(pubkeyx, sm2key->pubkey+1);
	BN_bn2bin(pubkeyy, sm2key->pubkey+33);
	BN_bn2bin(bnpri, sm2key->prikey);
	sm2key->sm2group = group;
	sm2key->sm2ptpubkey = ptpubkey;
	sm2key->sm2bnprikey = bnpri;

	return 0;
}

int qinn_sm2_enc(sm2_key_st *sm2key, unsigned char *msg, int msglen,
	unsigned char *cipher, int *cipher_len) {
	int ret;
	BIGNUM *k = NULL;
	BIGNUM *order = NULL;
	BIGNUM *c1x = NULL, *c1y = NULL;
	BIGNUM *c2x = NULL, *c2y = NULL;
	EC_POINT *ptc1 = NULL;
	EC_POINT *ptc2 = NULL;
	EC_GROUP *group = sm2key->sm2group;
	unsigned char c2buf[64] = { 0 };
	unsigned char *kdfbuf = NULL;
	unsigned char sm3buf[32] = {0};
	unsigned int sm3buf_len = sizeof(sm3buf);
	EVP_MD_CTX *ctx = NULL;
	int cursor = 0;
	

	order = EC_GROUP_get0_order(group);
	if (order == NULL) {
		return 1;
	}

	k = BN_new();
	c1x = BN_new();
	c1y = BN_new();
	c2x = BN_new();
	c2y = BN_new();
	BN_rand_range(k, order);

	ptc1 = EC_POINT_new(group);
	ptc2 = EC_POINT_new(group);
	ret = EC_POINT_mul(group, ptc1, k, NULL, NULL, NULL);
	if (ret != 1) {
		return ret;
	}

	ret = EC_POINT_mul(group, ptc2, NULL, sm2key->sm2ptpubkey, k, NULL);
	if (ret != 1) {
		return ret;
	}

	ret = EC_POINT_get_affine_coordinates_GFp(group, ptc2, c2x, c2y, NULL);
	if (ret != 1) {
		return ret;
	}

	BN_bn2bin(c2x, c2buf);
	BN_bn2bin(c2y, c2buf+32);

	kdfbuf = (unsigned char*)calloc(msglen, 1);
	ret = ECDH_KDF_X9_62(kdfbuf, (size_t)msglen, c2buf, sizeof(c2buf),
		NULL, 0, EVP_sm3());
	if (ret != 1) {
		return ret;
	}

	for (int i = 0; i < msglen; i++) {
		kdfbuf[i] ^= msg[i];
	}

	//hashbuf = (unsigned char*)calloc()
	ctx = EVP_MD_CTX_new();

	EVP_DigestInit_ex(ctx, EVP_sm3(), NULL);
	EVP_DigestUpdate(ctx, c2buf, 32);
	EVP_DigestUpdate(ctx, msg, msglen);
	EVP_DigestUpdate(ctx, c2buf + 32, 32);
	EVP_DigestFinal_ex(ctx, sm3buf, &sm3buf_len);

	ret = EC_POINT_get_affine_coordinates_GFp(group, ptc1, c1x, c1y, NULL);
	if (ret != 1) {
		return ret;
	}

	cipher[0] = 0x04;
	cursor += 1;

	BN_bn2bin(c1x, cipher + cursor);
	cursor += BN_num_bytes(c1x);

	BN_bn2bin(c1y, cipher + cursor);
	cursor += BN_num_bytes(c1y);

	memcpy(cipher + cursor, sm3buf, sizeof(sm3buf));
	cursor += sizeof(sm3buf);

	memcpy(cipher + cursor, kdfbuf, msglen);
	cursor += msglen;

	*cipher_len = cursor;

	return 0;
}

int qinn_sm2_dec(sm2_key_st *sm2key, unsigned char *cipher, int cipher_len, 
	unsigned char *plain, int *plain_len) {
	int ret;
	BIGNUM *g = NULL, *c1x = NULL, *c1y = NULL;
	int cursor = 1;
	EC_POINT *ptc1 = NULL;
	EC_POINT *ptc2 = NULL;
	BIGNUM *c2x = NULL, *c2y = NULL;
	unsigned char c2xy[64] = { 0 };
	unsigned char *kdfbuf = NULL;
	int kdfbuf_len = cipher_len - (65 + 32);
	EVP_MD_CTX *ctx = NULL;
	unsigned char sm3buf[32] = { 0 };
	int sm3buf_len = sizeof(sm3buf);
	EC_GROUP *group = sm2key->sm2group;

	g = BN_new();
	c1x = BN_new();
	c1y = BN_new();
	c2x = BN_new();
	c2y = BN_new();

	BN_bin2bn(cipher + cursor, 32, c1x);
	cursor += 32;

	BN_bin2bn(cipher + cursor, 32, c1y);
	cursor += 32;

	ptc1 = EC_POINT_new(group);
	ret = EC_POINT_set_affine_coordinates_GFp(group, ptc1, c1x, c1y, NULL);
	if (ret != 1) {
		return 1;
	}

	ptc2 = EC_POINT_new(group);

	ret = EC_POINT_mul(group, ptc2, NULL, ptc1, sm2key->sm2bnprikey, NULL);
	if (ret != 1) {
		return ret;
	}

	ret = EC_POINT_get_affine_coordinates_GFp(group, ptc2, c2x, c2y, NULL);
	if (ret != 1) {
		return 1;
	}

	BN_bn2bin(c2x, c2xy);
	BN_bn2bin(c2y, c2xy + 32);

	kdfbuf = (unsigned char*)calloc(kdfbuf_len, 1);

	ret = ECDH_KDF_X9_62(kdfbuf, kdfbuf_len, c2xy, sizeof(c2xy), NULL, 0, EVP_sm3());
	if (ret != 1) {
		return ret;
	}

	for (int i = 0; i < kdfbuf_len; i++) {
		kdfbuf[i] ^= cipher[97 + i];
	}

	ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx, EVP_sm3(), NULL);
	EVP_DigestUpdate(ctx, c2xy, 32);
	EVP_DigestUpdate(ctx, kdfbuf, kdfbuf_len);
	EVP_DigestUpdate(ctx, c2xy + 32, 32);
	EVP_DigestFinal_ex(ctx, sm3buf, &sm3buf_len);

	if (memcmp(cipher + 65, sm3buf, sm3buf_len) != 0) {
		return 1;
	}

	memcpy(plain, kdfbuf, kdfbuf_len);
	*plain_len = kdfbuf_len;

	return 0;
}

static BIGNUM* sm2_compute_z(sm2_key_st *sm2key, unsigned char *msg, int msglen) {
	int ret;
	unsigned char sm3buf[32] = { 0 };
	unsigned int digest_len = sizeof(sm3buf);
	EVP_MD_CTX *ctx = NULL;
	BIGNUM *bn = NULL;
	BIGNUM *bnret = NULL;
	BIGNUM *corx = NULL, *cory = NULL;
	unsigned char buf[32] = { 0 };
	EC_POINT *pt = NULL;
	EC_GROUP *gp = sm2key->sm2group;

	ctx = EVP_MD_CTX_new();
	pt = EC_GROUP_get0_generator(gp);
	corx = BN_new();
	cory = BN_new();
	bnret = BN_new();

	EVP_DigestInit_ex(ctx, EVP_sm3(), NULL);
	EVP_DigestUpdate(ctx, (uint8_t*)&sm2id_len, sizeof(sm2id_len));
	EVP_DigestUpdate(ctx, (uint8_t*)sm2id, sm2id_len);

	BN_hex2bn(&bn, sm2_a);
	BN_bn2bin(bn, buf);
	EVP_DigestUpdate(ctx, buf, 32);

	BN_hex2bn(&bn, sm2_b);
	BN_bn2bin(bn, buf);
	EVP_DigestUpdate(ctx, buf, 32);

	ret = EC_POINT_get_affine_coordinates_GFp(gp, pt, corx, cory, NULL);
	if (ret != 1) {
		return ret;
	}

	BN_bn2bin(corx, buf);
	EVP_DigestUpdate(ctx, buf, 32);

	BN_bn2bin(cory, buf);
	EVP_DigestUpdate(ctx, buf, 32);

	ret = EC_POINT_get_affine_coordinates_GFp(gp, sm2key->sm2ptpubkey, corx, cory, NULL);
	if (ret != 1) {
		return ret;
	}

	BN_bn2bin(corx, buf);
	EVP_DigestUpdate(ctx, buf, 32);

	BN_bn2bin(cory, buf);
	EVP_DigestUpdate(ctx, buf, 32);

	EVP_DigestUpdate(ctx, msg, msglen);
	EVP_DigestFinal(ctx, sm3buf, &digest_len);

	BN_bin2bn(sm3buf, digest_len, bnret);
	return bnret;
}

int qinn_sm2_sign(sm2_key_st *sm2key, unsigned char *msg, int msglen,
	unsigned char *sigr, unsigned char *sigs) {
	int ret, len;
	BIGNUM *k = NULL;
	BIGNUM *n = NULL;
	EC_POINT *kg = NULL;
	BIGNUM *kgx = NULL;
	BIGNUM *e = NULL, *r = NULL;
	BIGNUM *ksubrd = NULL;
	BIGNUM *rd = NULL;
	BIGNUM *inv = NULL, *s = NULL;
	BN_CTX *ctx = NULL;
	EC_GROUP *group = sm2key->sm2group;
	BIGNUM *one = NULL;
	BIGNUM * oneaddd = NULL;
	unsigned char buf[32] = { 0 };

	n = EC_GROUP_get0_order(group);
	if (n == NULL) {
		return 1;
	}

	k = BN_new();
	//ret = BN_priv_rand_range(k, n);
	ret = BN_rand_range(k, n);
	if (ret != 1) {
		return ret;
	}

	kg = EC_POINT_new(group);
	ret = EC_POINT_mul(group, kg, k, NULL, NULL, NULL);
	if (ret != 1) {
		return ret;
	}
	BN_bn2bin(k, buf);
	printf("sm2 sign k :\n");
	print_hex(buf, BN_num_bytes(k));

	kgx = BN_new();
	ret = EC_POINT_get_affine_coordinates_GFp(group, kg, kgx, NULL, NULL);
	if (ret != 1) {
		return ret;
	}
	BN_bn2bin(kgx, buf);
	printf("sm2 sign kgx :\n");
	print_hex(buf, BN_num_bytes(kgx));

	//r = e + x mod n
	ctx = BN_CTX_new();
	e = sm2_compute_z(sm2key, msg, msglen);

	BN_bn2bin(e, buf);
	printf("sm2 sign e :\n");
	print_hex(buf, BN_num_bytes(e));
	r = BN_new();
	ret = BN_mod_add(r, e, kgx, n, ctx);
	if (ret != 1) {
		return ret;
	}
	BN_bn2bin(r, buf);
	printf("sm2 sign r :\n");
	print_hex(buf, BN_num_bytes(r));

	//s = (inverse(1+da) * (k -r*da)) mod n
	rd = BN_new();
	ret = BN_mod_mul(rd, r, sm2key->sm2bnprikey, n, ctx);
	if (ret != 1) {
		return 1;
	}

	ksubrd = BN_new();
	ret = BN_mod_sub(ksubrd, k, rd, n, ctx);
	if (ret != 1) {
		return 1;
	}

	inv = BN_new();
	one = BN_new();
	oneaddd = BN_new();
	BN_one(one);
	BN_add(oneaddd, sm2key->sm2bnprikey, one);
	//BN_mod_add(oneaddd, sm2key->sm2bnprikey, one, n, ctx);
	BN_mod_inverse(inv, oneaddd, n, ctx);

	s = BN_new();
	ret = BN_mod_mul(s, inv, ksubrd, n, ctx);
	if (ret != 1) {
		return ret;
	}
	BN_bn2bin(s, buf);
	printf("sm2 sign s :\n");
	print_hex(buf, BN_num_bytes(s));

	len = BN_num_bytes(r);
	if (len != 32) {
		return 1;
	}
	BN_bn2bin(r, sigr);

	len = BN_num_bytes(s);
	if (len != 32) {
		return 1;
	}
	BN_bn2bin(s, sigs);

	return 0;
}

int qinn_sm2_verify(sm2_key_st *sm2key, unsigned char *msg, int msglen, 
	unsigned char *sigr, unsigned char *sigs) {
	int ret;
	BIGNUM *r = NULL, *s = NULL;
	BIGNUM *t = NULL;
	EC_GROUP *gp = sm2key->sm2group;
	BIGNUM *n = NULL;
	BN_CTX *ctx = NULL;
	EC_POINT *pt = NULL;
	BIGNUM *x = NULL;
	BIGNUM *e = NULL;
	BIGNUM *R = NULL;
	unsigned char buf[32] = { 0 };

	r = BN_new();
	s = BN_new();
	t = BN_new();
	n = BN_new();
	ctx = BN_CTX_new();
	pt = EC_POINT_new(gp);
	x = BN_new();
	R = BN_new();

	BN_bin2bn(sigr, 32, r);
	BN_bin2bn(sigs, 32, s);

	BN_bn2bin(r, buf);
	printf("sm2 verify r :\n");
	print_hex(buf, BN_num_bytes(r));

	BN_bn2bin(s, buf);
	printf("sm2 verify s :\n");
	print_hex(buf, BN_num_bytes(s));

	EC_GROUP_get_order(gp, n, NULL);
	ret = BN_mod_add(t, r, s, n, ctx);
	if (ret != 1) {
		return ret;
	}

	ret = EC_POINT_mul(gp, pt, s, sm2key->sm2ptpubkey, t, NULL);
	if (ret != 1) {
		return ret;
	}

	ret = EC_POINT_get_affine_coordinates_GFp(gp, pt, x, NULL, NULL);
	if (ret != 1) {
		return ret;
	}
	BN_bn2bin(x, buf);
	printf("sm2 verify x :\n");
	print_hex(buf, BN_num_bytes(x));

	e = sm2_compute_z(sm2key, msg, msglen);
	BN_bn2bin(e, buf);
	printf("sm2 verify e :\n");
	print_hex(buf, BN_num_bytes(e));

	BN_mod_add(R, e, x, n, ctx);
	BN_bn2bin(R, buf);
	printf("sm2 verify R :\n");
	print_hex(buf, BN_num_bytes(R));

	if (BN_cmp(r, R) != 0) {
		return 1;
	}

	return 0;
}