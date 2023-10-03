#include "mxpresenterlist.h"
#include "mxpresenter.h"

DECOMP_SIZE_ASSERT(MxPresenterList, 0x18);
DECOMP_SIZE_ASSERT(MxPresenterListCursor, 0x10);

// OFFSET: LEGO1 0x1001cd00
MxS8 MxPresenterList::Compare(MxPresenter *p_var0, MxPresenter *p_var1)
{
  if (p_var1 == p_var0)
    return 0;
  if (p_var1 <= p_var0)
    return 1;
  return -1;
}
