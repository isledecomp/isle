
#include "matrix.h"

#include "../decomp.h"
#include "math.h"

#include <memory.h>

DECOMP_SIZE_ASSERT(Matrix4, 0x40);
DECOMP_SIZE_ASSERT(Matrix4Impl, 0x8);
DECOMP_SIZE_ASSERT(Matrix4Data, 0x48);
