#ifndef LEGOENTITYLIST_H
#define LEGOENTITYLIST_H

#include "mxlist.h"
#include "mxtypes.h"

class LegoEntity;

// VTABLE: LEGO1 0x100d6410
// class MxCollection<LegoEntity *>

// VTABLE: LEGO1 0x100d6428
// class MxList<LegoEntity *>

// VTABLE: LEGO1 0x100d6440
// class MxPtrList<LegoEntity>

// VTABLE: LEGO1 0x100d6458
// SIZE 0x18
class LegoEntityList : public MxPtrList<LegoEntity> {
public:
	LegoEntityList(MxBool p_ownership = FALSE) : MxPtrList<LegoEntity>(p_ownership) {}

	// FUNCTION: LEGO1 0x1001e2d0
	virtual MxS8 Compare(LegoEntity* p_a, LegoEntity* p_b) override
	{
		return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
	}; // vtable+0x14
};

// VTABLE: LEGO1 0x100d64e8
// class MxListCursor<LegoEntity *>

// VTABLE: LEGO1 0x100d64b8
// class MxPtrListCursor<LegoEntity>

// VTABLE: LEGO1 0x100d64d0
// SIZE 0x10
class LegoEntityListCursor : public MxPtrListCursor<LegoEntity> {
public:
	LegoEntityListCursor(LegoEntityList* p_list) : MxPtrListCursor<LegoEntity>(p_list){};
};

// TEMPLATE: LEGO1 0x1001e2f0
// MxCollection<LegoEntity *>::Compare

// TEMPLATE: LEGO1 0x1001e300
// MxCollection<LegoEntity *>::~MxCollection<LegoEntity *>

// TEMPLATE: LEGO1 0x1001e350
// MxCollection<LegoEntity *>::Destroy

// TEMPLATE: LEGO1 0x1001e360
// MxList<LegoEntity *>::~MxList<LegoEntity *>

// TEMPLATE: LEGO1 0x1001e3f0
// MxPtrList<LegoEntity>::Destroy

// SYNTHETIC: LEGO1 0x1001e400
// LegoEntityList::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1001e470
// MxPtrList<LegoEntity>::~MxPtrList<LegoEntity>

// SYNTHETIC: LEGO1 0x1001e4c0
// MxCollection<LegoEntity *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001e530
// MxList<LegoEntity *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001e5e0
// MxPtrList<LegoEntity>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001f110
// LegoEntityListCursor::`scalar deleting destructor'

// FUNCTION: LEGO1 0x1001f180
// MxPtrListCursor<LegoEntity>::~MxPtrListCursor<LegoEntity>

// SYNTHETIC: LEGO1 0x1001f1d0
// MxListCursor<LegoEntity *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001f240
// MxPtrListCursor<LegoEntity>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x1001f2b0
// MxListCursor<LegoEntity *>::~MxListCursor<LegoEntity *>

// FUNCTION: LEGO1 0x1001edc6
// LegoEntityListCursor::~LegoEntityListCursor

#endif // LEGOENTITYLIST_H
