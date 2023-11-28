#include "mxpresenterlist.h"

#include "mxpresenter.h"

DECOMP_SIZE_ASSERT(MxPresenterList, 0x18);
DECOMP_SIZE_ASSERT(MxPresenterListCursor, 0x10);

// FUNCTION: LEGO1 0x1001cd00
MxS8 MxPresenterList::Compare(MxPresenter* p_a, MxPresenter* p_b)
{
	return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
}

// FUNCTION: LEGO1 0x1001cd20 SYNTHETIC
// MxCollection<MxPresenter *>::Compare

// FUNCTION: LEGO1 0x1001cd30 SYNTHETIC
// MxCollection<MxPresenter *>::Destroy

// FUNCTION: LEGO1 0x1001cd40 SYNTHETIC
// MxList<MxPresenter *>::MxList<MxPresenter *>

// FUNCTION: LEGO1 0x1001cdd0 SYNTHETIC
// MxCollection<MxPresenter *>::~MxCollection<MxPresenter *>

// FUNCTION: LEGO1 0x1001ce20 SYNTHETIC
// MxList<MxPresenter *>::~MxList<MxPresenter *>

// FUNCTION: LEGO1 0x1001cf70 SYNTHETIC
// MxCollection<MxPresenter *>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x1001cfe0 SYNTHETIC
// MxList<MxPresenter *>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x1001d090 SYNTHETIC
// MxPtrList<MxPresenter>::`scalar deleting destructor'
