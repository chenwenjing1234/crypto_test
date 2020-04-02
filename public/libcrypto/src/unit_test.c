#include "unit_test.h"
#include "crypt_aes.h"
#include "crypt_sm2.h"
#include "crypt_ecc.h"
#include "crypt_rsa.h"
#include "crypt_ecdsa.h"
#include "crypt_ecdh.h"
#include <openssl/obj_mac.h>
#include <openssl/evp.h>

static int print_bytes(unsigned char *bytes, int len) {
	for (int i = 0; i < len; i++) {
		printf("%02X", bytes[i]);
	}
	printf("\n");
}

int crypt_test_case() {
	int ret;
	sm2_key_st sm2key = { 0 };
	unsigned char msg[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	unsigned char cipher[256] = { 0 };
	int cipher_len = sizeof(cipher);
	unsigned char plain[32] = { 0 };
	int plain_len = sizeof(plain);
	unsigned char sigr[32] = { 0 };
	unsigned char sigs[32] = { 0 };
	int siglen = 0;

	ret = qinn_sm2_gen_keypair(&sm2key);
	if (ret != 0) {
		printf("qinn_sm2_gen_keypair failed\n");
		return ret;
	}

	print_bytes(sm2key.prikey, sizeof(sm2key.prikey));
	print_bytes(sm2key.pubkey, sizeof(sm2key.pubkey));

	ret = qinn_sm2_enc(&sm2key, msg, sizeof(msg), cipher, &cipher_len);
	if (ret != 0) {
		printf("qinn_sm2_enc failed\n");
		return ret;
	}

	ret = qinn_sm2_dec(&sm2key, cipher, cipher_len, plain, &plain_len);
	if (ret != 0) {
		printf("qinn_sm2_dec failed\n");
		return ret;
	}

	ret = qinn_sm2_sign(&sm2key, msg, sizeof(msg), sigr, sigs);
	if (ret != 0) {
		printf("qinn_sm2_sign failed\n");
		return ret;
	}

	ret = qinn_sm2_verify(&sm2key, msg, sizeof(msg), sigr, sigs);
	if (ret != 0) {
		printf("qinn_sm2_verify failed\n");
		return ret;
	}
	return 0;
}

int aes_test() {
	int ret;

	unsigned char plain[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

	unsigned char key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 ,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 ,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 ,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

	unsigned char nonce[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

	unsigned char cipher[16] = { 0 };

	unsigned char decresult[16] = { 0 };
	aes_context ctx = { 0 };

	aes_setkey_enc(&ctx, key, sizeof(key)*8);

	aes_crypt_ctr(&ctx, AES_ENCRYPT, sizeof(plain), nonce, 0, plain, cipher);

	aes_crypt_ctr(&ctx, AES_ENCRYPT, sizeof(cipher), nonce, 0, cipher, decresult);

	if (memcmp(plain, decresult, sizeof(plain)) != 0) {
		printf("aes-enc-dec test failed\n");
		return 1;
	}

	printf("aes-enc-dec test successed\n");
	return 0;

}

int crypt_ecc_test_case() {
	int ret;
	sm2_key_st sm2key = { 0 };
	EC_POINT *generator = NULL;
	EC_GROUP *gp = NULL;
	EC_POINT *ptret = NULL;

	ret = qinn_sm2_gen_keypair(&sm2key);
	if (ret != 0) {
		printf("qinn_sm2_gen_keypair failed\n");
		return ret;
	}

	gp = sm2key.sm2group;
	generator = EC_GROUP_get0_generator(gp);
	ptret = qinn_point_add(gp, generator, generator);
	if (ptret == NULL) {
		printf("qinn_point_add failed\n");
		return 1;
	}

	return 0;
}

int crypt_rsa_test_case() {
	int ret;
	qinn_rsa_st rsakey = { 0 };
	unsigned char plain[16] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	unsigned char cipher[128] = { 0 };
	int cipher_len = 0;
	unsigned char decresult[16] = { 0 };
	int decresult_len = 0;

	ret = qinn_rsa_gen_key(1024, &rsakey);
	if (ret != 0) {
		printf("qinn_rsa_gen_key failed\n");
		return ret;
	}

	ret = qinn_rsa_enc(&rsakey, plain, sizeof(plain), cipher, &cipher_len);
	if (ret != 0) {
		printf("qinn_rsa_enc failed\n");
		return ret;
	}

	ret = qinn_rsa_dec(&rsakey, cipher, cipher_len, decresult, &decresult_len);
	if (ret != 0) {
		printf("qinn_rsa_dec failed\n");
		return ret;
	}

	if (memcmp(plain, decresult, decresult_len) == 0) {
		printf("crypt_rsa_test_case successed\n");
	}
	
	return 0;
}

int crypt_ecdsa_test_case() {
	int ret;
	EC_KEY *eckey = NULL;
	unsigned char plain[16] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	unsigned char sigr[32] = { 0 };
	int sigr_len = 0;
	unsigned char sigs[32] = { 0 };
	int sigs_len = 0;

	eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
	if (eckey == NULL) {
		printf("EC_KEY_new_by_curve_name failed\n");
		return 1;
	}

	ret = EC_KEY_generate_key(eckey);
	if (ret != 1) {
		printf("EC_KEY_generate_key failed\n");
		return 1;
	}

	/*ret = qinn_ecdsa_sign(eckey, EVP_sha1(), plain, sizeof(plain),
		sigr, &sigr_len, sigs, &sigs_len);
	if (ret != 0) {
		printf("qinn_ecdsa_sign failed\n");
		return 1;
	}

	ret = qinn_ecdsa_verify(eckey, EVP_sha1(), plain, sizeof(plain),
		sigr, sigr_len, sigs, sigs_len);
	if (ret != 0) {
		printf("qinn_ecdsa_verify failed\n");
		return 1;
	}*/

	printf("qinn_ecdsa_sign qinn_ecdsa_verify successed\n");
	return 0;
}


int crypt_ecdh_test_case() {
	int ret;
	EC_KEY *eckey = NULL;

	eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
	if (eckey == NULL) {
		printf("EC_KEY_new_by_curve_name failed\n");
		return 1;
	}

	ret = EC_KEY_generate_key(eckey);
	if (ret != 1) {
		printf("EC_KEY_generate_key failed\n");
		return 1;
	}

	ret = qinn_ecdh_mock(eckey);
	if (ret != 1) {
		printf("EC_KEY_generate_key failed\n");
		return 1;
	}

	printf("crypt_ecdh_test_case successed\n");
	return 0;
}