#ifndef __CRYPT_ECC_H
#define __CRYPT_ECC_H

#include <openssl/ec.h>

EC_POINT* qinn_point_add(EC_GROUP *gp, EC_POINT *p1, EC_POINT *p2);




#endif