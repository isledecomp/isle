#ifndef LEGOPATHCONTROLLERLIST_H
#define LEGOPATHCONTROLLERLIST_H

#include "legopathcontroller.h"
#include "mxlist.h"
#include "mxtypes.h"

// VTABLE: LEGO1 0x100d6320 SYNTHETIC
// class MxPtrList<LegoPathController>

// VTABLE: LEGO1 0x100d6338
// SIZE 0x18
class LegoPathControllerList : public MxPtrList<LegoPathController> {
public:
	LegoPathControllerList() : MxPtrList<LegoPathController>(Destroy) {}
	virtual MxS8 Compare(LegoPathController*, LegoPathController*) override; // vtable+0x14
	static void Destroy(LegoPathController*);
};

// VTABLE: LEGO1 0x100d6380 SYNTHETIC
// class MxCollection<LegoPathController *>

// VTABLE: LEGO1 0x100d6398 SYNTHETIC
// class MxList<LegoPathController *>

#endif // LEGOPATHCONTROLLERLIST_H
