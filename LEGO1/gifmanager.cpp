#include "gifmanager.h"

DECOMP_SIZE_ASSERT(GifData, 0x14);
DECOMP_SIZE_ASSERT(GifMapEntry, 0x14);
DECOMP_SIZE_ASSERT(GifMap, 0x08);
DECOMP_SIZE_ASSERT(GifManagerBase, 0x10);
DECOMP_SIZE_ASSERT(GifManager, 0x24);

GifMapEntry* DAT_100f0100;
