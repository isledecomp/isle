#include "mxdsactionlist.h"
#include "mxdsaction.h"

DECOMP_SIZE_ASSERT(MxDSActionList, 0x1c);

// OFFSET: LEGO1 0x100c9c90
MxS8 MxDSActionList::Compare(MxDSAction *p_var0, MxDSAction *p_var1)
{
  if (p_var1 == p_var0)
    return 0;
  if (p_var1 <= p_var0)
    return 1;
  return -1;
}