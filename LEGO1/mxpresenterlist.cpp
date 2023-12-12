#include "mxpresenterlist.h"

#include "mxpresenter.h"

DECOMP_SIZE_ASSERT(MxPresenterList, 0x18);
DECOMP_SIZE_ASSERT(MxPresenterListCursor, 0x10);

// FUNCTION: LEGO1 0x1001cd00
MxS8 MxPresenterList::Compare(MxPresenter* p_a, MxPresenter* p_b)
{
	return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
}
