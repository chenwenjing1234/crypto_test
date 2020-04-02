#include "crypt_ecc.h"

EC_POINT* qinn_point_add(EC_GROUP *gp, EC_POINT *a, EC_POINT *b) {
	int ret;
	EC_POINT *pt = NULL;
	BN_CTX *ctx = NULL;

	pt = EC_POINT_new(gp);
	ctx = BN_CTX_new();

	ret = EC_POINT_add(gp, pt, a, b, ctx);
	if (ret != 1) {
		return NULL;
	}
	return ret;
}