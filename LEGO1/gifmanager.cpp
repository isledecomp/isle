#include "gifmanager.h"

DECOMP_SIZE_ASSERT(GifData, 0x14);
DECOMP_SIZE_ASSERT(GifMapEntry, 0x14);
DECOMP_SIZE_ASSERT(GifMap, 0x08);
DECOMP_SIZE_ASSERT(GifManagerBase, 0x14);
DECOMP_SIZE_ASSERT(GifManager, 0x30);

GifMapEntry *DAT_100f0100;

// OFFSET: LEGO1 0x10001cc0
GifMapEntry *GifMap::FindNode(const char *&string)
{
  GifMapEntry *ret = m_unk4;
  GifMapEntry *current = ret->m_parent;
  while (current != DAT_100f0100) {
    if (strcmp(current->m_key, string) <= 0) {
      ret = current;
      current = current->m_right;
    }
    else
      current = current->m_left;
  }
  return ret;
}