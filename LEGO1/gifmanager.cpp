#include "gifmanager.h"

// OFFSET: LEGO1 0x10001cc0
GifMapEntry *GifMap::FindNode(const char *&string)
{
  GifMapEntry *ret = m_unk4;
  GifMapEntry *current = ret->parent;
  while (current != DAT_100f0100) {
    if (strcmp(current->key, string) <= 0) {
      ret = current;
      current = current->right;
    }
    else current = current->left;
  }
  return ret;
}

GifMapEntry *DAT_100f0100;
