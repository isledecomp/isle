#ifndef LEGOPATHCONTROLLERLIST_H
#define LEGOPATHCONTROLLERLIST_H

#include "legopathcontroller.h"
#include "mxlist.h"
#include "mxtypes.h"

// VTABLE 0x100d6320 TEMPLATE
// class MxPtrList<LegoPathController>

// VTABLE 0x100d6338
// SIZE 0x18
class LegoPathControllerList : public MxPtrList<LegoPathController> {
public:
	LegoPathControllerList() : MxPtrList<LegoPathController>(Destroy) {}
	virtual MxS8 Compare(LegoPathController*, LegoPathController*) override; // vtable+0x14
	static void Destroy(LegoPathController*);
};

// VTABLE 0x100d6380 TEMPLATE
// class MxCollection<LegoPathController *>

// VTABLE 0x100d6398 TEMPLATE
// class MxList<LegoPathController *>

#endif // LEGOPATHCONTROLLERLIST_H
