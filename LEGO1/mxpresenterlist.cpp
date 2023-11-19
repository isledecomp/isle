#include "mxpresenterlist.h"

#include "mxpresenter.h"

DECOMP_SIZE_ASSERT(MxPresenterList, 0x18);
DECOMP_SIZE_ASSERT(MxPresenterListCursor, 0x10);

// OFFSET: LEGO1 0x1001cd00
MxS8 MxPresenterList::Compare(MxPresenter* p_a, MxPresenter* p_b)
{
	return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
}

// OFFSET: LEGO1 0x1001cd20 TEMPLATE
// MxCollection<MxPresenter *>::Compare

// OFFSET: LEGO1 0x1001cd30 TEMPLATE
// MxCollection<MxPresenter *>::Destroy

// OFFSET: LEGO1 0x1001cd40 TEMPLATE
// MxList<MxPresenter *>::MxList<MxPresenter *>

// OFFSET: LEGO1 0x1001cdd0 TEMPLATE
// MxCollection<MxPresenter *>::~MxCollection<MxPresenter *>

// OFFSET: LEGO1 0x1001ce20 TEMPLATE
// MxList<MxPresenter *>::~MxList<MxPresenter *>

// OFFSET: LEGO1 0x1001cf70 TEMPLATE
// MxCollection<MxPresenter *>::`scalar deleting destructor'

// OFFSET: LEGO1 0x1001cfe0 TEMPLATE
// MxList<MxPresenter *>::`scalar deleting destructor'

// OFFSET: LEGO1 0x1001d090 TEMPLATE
// MxPtrList<MxPresenter>::`scalar deleting destructor'
