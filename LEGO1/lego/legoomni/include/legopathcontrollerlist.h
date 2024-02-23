#ifndef LEGOPATHCONTROLLERLIST_H
#define LEGOPATHCONTROLLERLIST_H

#include "legopathcontroller.h"
#include "mxlist.h"
#include "mxtypes.h"

// VTABLE: LEGO1 0x100d6380
// class MxCollection<LegoPathController *>

// VTABLE: LEGO1 0x100d6398
// class MxList<LegoPathController *>

// VTABLE: LEGO1 0x100d6320
// class MxPtrList<LegoPathController>

// VTABLE: LEGO1 0x100d6338
// SIZE 0x18
class LegoPathControllerList : public MxPtrList<LegoPathController> {
public:
	LegoPathControllerList(MxBool p_ownership = FALSE) : MxPtrList<LegoPathController>(p_ownership) {}

	// FUNCTION: LEGO1 0x1001d210
	MxS8 Compare(LegoPathController* p_a, LegoPathController* p_b) override
	{
		return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
	} // vtable+0x14
};

// VTABLE: LEGO1 0x100d6578
// class MxListCursor<LegoPathController *>

// VTABLE: LEGO1 0x100d6548
// class MxPtrListCursor<LegoPathController>

// VTABLE: LEGO1 0x100d6560
// SIZE 0x10
class LegoPathControllerListCursor : public MxPtrListCursor<LegoPathController> {
public:
	LegoPathControllerListCursor(LegoPathControllerList* p_list) : MxPtrListCursor<LegoPathController>(p_list){};
};

// TEMPLATE: LEGO1 0x1001d230
// MxCollection<LegoPathController *>::Compare

// TEMPLATE: LEGO1 0x1001d240
// MxList<LegoPathController *>::MxList<LegoPathController *>

// TEMPLATE: LEGO1 0x1001d2d0
// MxCollection<LegoPathController *>::~MxCollection<LegoPathController *>

// TEMPLATE: LEGO1 0x1001d320
// MxCollection<LegoPathController *>::Destroy

// TEMPLATE: LEGO1 0x1001d330
// MxList<LegoPathController *>::~MxList<LegoPathController *>

// TEMPLATE: LEGO1 0x1001d3c0
// MxPtrList<LegoPathController>::Destroy

// SYNTHETIC: LEGO1 0x1001d3d0
// LegoPathControllerList::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1001d440
// MxPtrList<LegoPathController>::~MxPtrList<LegoPathController>

// SYNTHETIC: LEGO1 0x1001d490
// MxCollection<LegoPathController *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001d500
// MxList<LegoPathController *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001d5b0
// MxPtrList<LegoPathController>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001d620
// LegoPathControllerList::~LegoPathControllerList

// SYNTHETIC: LEGO1 0x1001f830
// LegoPathControllerListCursor::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1001f8a0
// MxPtrListCursor<LegoPathController>::~MxPtrListCursor<LegoPathController>

// SYNTHETIC: LEGO1 0x1001f8f0
// MxListCursor<LegoPathController *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001f960
// MxPtrListCursor<LegoPathController>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1001f9d0
// MxListCursor<LegoPathController *>::~MxListCursor<LegoPathController *>

// FUNCTION: LEGO1 0x1001fa20
// LegoPathControllerListCursor::~LegoPathControllerListCursor

#endif // LEGOPATHCONTROLLERLIST_H
