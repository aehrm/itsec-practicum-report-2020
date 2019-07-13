typedef int int128_t __attribute__((mode(TI)));
typedef unsigned int uint128_t __attribute__((mode(TI)));

#define USE_FIELD_5X52
#define USE_NUM_GMP
#define USE_FIELD_INV_NUM
#define USE_SCALAR_4X64
#define USE_SCALAR_INV_NUM
#define USE_ASM_X86_64
#define ECMULT_WINDOW_SIZE 24
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/src/num.h"
#include "secp256k1/src/num_impl.h"
#include "secp256k1/src/num_gmp_impl.h"
#include "secp256k1/src/field_impl.h"
#include "secp256k1/src/group_impl.h"
#include "secp256k1/src/scalar_impl.h"
#include "secp256k1/src/ecmult_impl.h"
#include "secp256k1/src/ecmult_const_impl.h"
#include "secp256k1/src/eckey_impl.h"
