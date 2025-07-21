#ifndef MXPRESENTERLIST_H
#define MXPRESENTERLIST_H

#include "mxlist.h"
#include "mxpresenter.h"

// VTABLE: LEGO1 0x100d62f0
// VTABLE: BETA10 0x101bf070
// class MxPtrList<MxPresenter>

// VTABLE: LEGO1 0x100d6308
// VTABLE: BETA10 0x101bf050
// SIZE 0x18
class MxPresenterList : public MxPtrList<MxPresenter> {
public:
	// FUNCTION: BETA10 0x100dc900
	MxPresenterList(MxBool p_ownership = FALSE) : MxPtrList<MxPresenter>(p_ownership) {}

	// FUNCTION: LEGO1 0x1001cd00
	MxS8 Compare(MxPresenter* p_a, MxPresenter* p_b) override
	{
		return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
	} // vtable+0x14

	// SYNTHETIC: LEGO1 0x1001ceb0
	// MxPresenterList::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100d6488
// class MxListCursor<MxPresenter *>

// VTABLE: LEGO1 0x100d6530
// class MxPtrListCursor<MxPresenter>

// VTABLE: LEGO1 0x100d6470
// SIZE 0x10
class MxPresenterListCursor : public MxPtrListCursor<MxPresenter> {
public:
	// FUNCTION: BETA10 0x1007d130
	MxPresenterListCursor(MxPresenterList* p_list) : MxPtrListCursor<MxPresenter>(p_list) {}

	// SYNTHETIC: LEGO1 0x1001eed0
	// MxPresenterListCursor::`scalar deleting destructor'

	// SYNTHETIC: LEGO1 0x1001f0c0
	// SYNTHETIC: BETA10 0x1007d510
	// MxPresenterListCursor::~MxPresenterListCursor
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

// TEMPLATE: BETA10 0x100dc9f0
// MxPtrList<MxPresenter>::MxPtrList<MxPresenter>

// TEMPLATE: LEGO1 0x1001cf20
// TEMPLATE: BETA10 0x100dce70
// MxPtrList<MxPresenter>::~MxPtrList<MxPresenter>

// SYNTHETIC: LEGO1 0x1001cf70
// MxCollection<MxPresenter *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001cfe0
// MxList<MxPresenter *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001d090
// MxPtrList<MxPresenter>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001d100
// MxPresenterList::~MxPresenterList

// TEMPLATE: LEGO1 0x1001ef40
// TEMPLATE: BETA10 0x1007d370
// MxPtrListCursor<MxPresenter>::~MxPtrListCursor<MxPresenter>

// SYNTHETIC: LEGO1 0x1001ef90
// MxListCursor<MxPresenter *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001f000
// MxPtrListCursor<MxPresenter>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1001f070
// TEMPLATE: BETA10 0x1007d490
// MxListCursor<MxPresenter *>::~MxListCursor<MxPresenter *>

// TEMPLATE: LEGO1 0x10020760
// MxListCursor<MxPresenter *>::MxListCursor<MxPresenter *>

// TEMPLATE: LEGO1 0x10022380
// MxList<MxPresenter *>::InsertEntry

// TEMPLATE: LEGO1 0x100225e0
// MxList<MxPresenter *>::DeleteEntry

// TEMPLATE: BETA10 0x1007d1d0
// MxPtrListCursor<MxPresenter>::MxPtrListCursor<MxPresenter>

// TEMPLATE: BETA10 0x1007d270
// MxListCursor<MxPresenter *>::MxListCursor<MxPresenter *>

// TEMPLATE: BETA10 0x1007dc60
// MxListCursor<MxPresenter *>::Next

// TEMPLATE: BETA10 0x100d8f20
// MxListCursor<MxPresenter *>::Reset

// TEMPLATE: BETA10 0x1007e070
// MxListEntry<MxPresenter *>::GetNext

// TEMPLATE: BETA10 0x1007e0a0
// MxListEntry<MxPresenter *>::GetValue

// TEMPLATE: BETA10 0x100d9420
// ?Prev@?$MxListCursor@PAVMxPresenter@@@@QAEEAAPAVMxPresenter@@@Z

#endif // MXPRESENTERLIST_H
