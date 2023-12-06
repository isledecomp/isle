#include "mxpresenterlist.h"

#include "mxpresenter.h"

DECOMP_SIZE_ASSERT(MxPresenterList, 0x18);
DECOMP_SIZE_ASSERT(MxPresenterListCursor, 0x10);

// FUNCTION: LEGO1 0x1001cd00
MxS8 MxPresenterList::Compare(MxPresenter* p_a, MxPresenter* p_b)
{
	return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
}

// TEMPLATE: LEGO1 0x1001cd20
// MxCollection<MxPresenter *>::Compare

// TEMPLATE: LEGO1 0x1001cd30
// MxCollection<MxPresenter *>::Destroy

// TEMPLATE: LEGO1 0x1001cd40
// MxList<MxPresenter *>::MxList<MxPresenter *>

// TEMPLATE: LEGO1 0x1001cdd0
// MxCollection<MxPresenter *>::~MxCollection<MxPresenter *>

// TEMPLATE: LEGO1 0x1001ce20
// MxList<MxPresenter *>::~MxList<MxPresenter *>

// SYNTHETIC: LEGO1 0x1001cf70
// MxCollection<MxPresenter *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001cfe0
// MxList<MxPresenter *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001d090
// MxPtrList<MxPresenter>::`scalar deleting destructor'
