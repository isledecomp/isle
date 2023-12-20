#ifndef MXPRESENTERLIST_H
#define MXPRESENTERLIST_H

#include "mxlist.h"
#include "mxpresenter.h"

// VTABLE: LEGO1 0x100d62f0
// class MxPtrList<MxPresenter>

// VTABLE: LEGO1 0x100d6308
// SIZE 0x18
class MxPresenterList : public MxPtrList<MxPresenter> {
public:
	MxPresenterList(MxBool p_ownership = FALSE) : MxPtrList<MxPresenter>(p_ownership) {}

	// FUNCTION: LEGO1 0x1001cd00
	virtual MxS8 Compare(MxPresenter* p_a, MxPresenter* p_b) override
	{
		return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
	}; // vtable+0x14
};

// VTABLE: LEGO1 0x100d6488
// class MxListCursor<MxPresenter *>

// VTABLE: LEGO1 0x100d6530
// class MxPtrListCursor<MxPresenter>

// VTABLE: LEGO1 0x100d6470
class MxPresenterListCursor : public MxPtrListCursor<MxPresenter> {
public:
	MxPresenterListCursor(MxPresenterList* p_list) : MxPtrListCursor<MxPresenter>(p_list){};
};

// VTABLE: LEGO1 0x100d6350
// class MxCollection<MxPresenter *>

// VTABLE: LEGO1 0x100d6368
// class MxList<MxPresenter *>

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

#endif // MXPRESENTERLIST_H
