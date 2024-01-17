#ifndef MXCORELIST_H
#define MXCORELIST_H

#include "mxlist.h"
#include "mxtypes.h"

class MxCore;

// VTABLE: LEGO1 0x100d63b0
// class MxCollection<MxCore *>

// VTABLE: LEGO1 0x100d63c8
// class MxList<MxCore *>

// VTABLE: LEGO1 0x100d63e0
// class MxPtrList<MxCore>

// VTABLE: LEGO1 0x100d63f8
// SIZE 0x18
class MxCoreList : public MxPtrList<MxCore> {
public:
	MxCoreList(MxBool p_ownership = FALSE) : MxPtrList<MxCore>(p_ownership) {}

	// FUNCTION: LEGO1 0x1001e650
	virtual MxS8 Compare(MxCore* p_a, MxCore* p_b) override
	{
		return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
	}; // vtable+0x14
};

// VTABLE: LEGO1 0x100d64a0
// class MxListCursor<MxCore *>

// VTABLE: LEGO1 0x100d6500
// class MxPtrListCursor<MxCore>

// VTABLE: LEGO1 0x100d6518
// SIZE 0x10
class MxCoreListCursor : public MxPtrListCursor<MxCore> {
public:
	MxCoreListCursor(MxCoreList* p_list) : MxPtrListCursor<MxCore>(p_list){};
};

// TEMPLATE: LEGO1 0x1001e670
// MxCollection<MxCore *>::Compare

// TEMPLATE: LEGO1 0x1001e680
// MxCollection<MxCore *>::~MxCollection<MxCore *>

// TEMPLATE: LEGO1 0x1001e6d0
// MxCollection<MxCore *>::Destroy

// TEMPLATE: LEGO1 0x1001e6e0
// MxList<MxCore *>::~MxList<MxCore *>

// TEMPLATE: LEGO1 0x1001e770
// MxPtrList<MxCore>::Destroy

// SYNTHETIC: LEGO1 0x1001e780
// MxCoreList::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1001e7f0
// MxPtrList<MxCore>::~MxPtrList<MxCore>

// SYNTHETIC: LEGO1 0x1001e840
// MxCollection<MxCore *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001e8b0
// MxList<MxCore *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001e960
// MxPtrList<MxCore>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001f350
// MxCoreListCursor::`scalar deleting destructor'

// FUNCTION: LEGO1 0x1001f3c0
// MxPtrListCursor<MxCore>::~MxPtrListCursor<MxCore>

// SYNTHETIC: LEGO1 0x1001f410
// MxListCursor<MxCore *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001f480
// MxPtrListCursor<MxCore>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x1001f4f0
// MxListCursor<MxCore *>::~MxListCursor<MxCore *>

// FUNCTION: LEGO1 0x1001f540
// MxCoreListCursor::~MxCoreListCursor

// TEMPLATE: LEGO1 0x10020840
// MxListCursor<MxCore *>::MxListCursor<MxCore *>

#endif // MXCORELIST_H
