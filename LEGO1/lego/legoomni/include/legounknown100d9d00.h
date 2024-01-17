#ifndef LEGOUNKNOWN100D9D00_H
#define LEGOUNKNOWN100D9D00_H

#include "decomp.h"
#include "legounknown100d7c88.h"
#include "mxlist.h"

// VTABLE: LEGO1 0x100d9cd0
// class MxCollection<LegoUnknown100d7c88 *>

// VTABLE: LEGO1 0x100d9ce8
// class MxList<LegoUnknown100d7c88 *>

// VTABLE: LEGO1 0x100d9d00
// SIZE 0x18
class LegoUnknown100d9d00 : public MxList<LegoUnknown100d7c88*> {
public:
	LegoUnknown100d9d00() { SetDestroy(Destroy); }

	// STUB: LEGO1 0x1007b210
	virtual MxS8 Compare(LegoUnknown100d7c88* p_a, LegoUnknown100d7c88* p_b) override { return -1; } // vtable+0x14

	// FUNCTION: LEGO1 0x1007b2e0
	static void Destroy(LegoUnknown100d7c88* p_element) { delete p_element; }
};

// TEMPLATE: LEGO1 0x1007b300
// MxCollection<LegoUnknown100d7c88 *>::Compare

// TEMPLATE: LEGO1 0x1007b310
// MxCollection<LegoUnknown100d7c88 *>::~MxCollection<LegoUnknown100d7c88 *>

// TEMPLATE: LEGO1 0x1007b360
// MxCollection<LegoUnknown100d7c88 *>::Destroy

// TEMPLATE: LEGO1 0x1007b370
// MxList<LegoUnknown100d7c88 *>::~MxList<LegoUnknown100d7c88 *>

// SYNTHETIC: LEGO1 0x1007b400
// LegoUnknown100d9d00::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1007b470
// MxCollection<LegoUnknown100d7c88 *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1007b4e0
// MxList<LegoUnknown100d7c88 *>::`scalar deleting destructor'

#endif // LEGOUNKNOWN100D9D00_H
