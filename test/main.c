
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "unit_test.h"

int main(int argc, char *argv[]) {
	int ret;
	
	printf("main invoked\n");

	ret = crypt_ecdh_test_case();

	//ret = crypt_ecdsa_test_case();

	//ret = crypt_rsa_test_case();

	//ret = crypt_ecc_test_case();

	//ret = crypt_test_case();

	//ret = aes_test();
		

	return 0;
}