#include "mxdsactionlist.h"
#include "mxdsaction.h"

DECOMP_SIZE_ASSERT(MxDSActionList, 0x1c);
DECOMP_SIZE_ASSERT(MxDSActionListCursor, 0x10);

// OFFSET: LEGO1 0x100c9c90
MxS8 MxDSActionList::Compare(MxDSAction *p_var0, MxDSAction *p_var1)
{
  if (p_var1 == p_var0)
    return 0;
  if (p_var1 <= p_var0)
    return 1;
  return -1;
}

// OFFSET: LEGO1 0x100c9cb0
void MxDSActionList::Destroy(MxDSAction *p_action)
{
  if (p_action)
    delete p_action;
}