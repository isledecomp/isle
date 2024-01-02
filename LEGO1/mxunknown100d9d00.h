#ifndef MXUNKNOWN100D9D00_H
#define MXUNKNOWN100D9D00_H

#include "decomp.h"
#include "mxlist.h"
#include "mxunknown100d7c88.h"

// VTABLE: LEGO1 0x100d9cd0
// class MxCollection<MxUnknown100d7c88 *>

// VTABLE: LEGO1 0x100d9ce8
// class MxList<MxUnknown100d7c88 *>

// VTABLE: LEGO1 0x100d9d00
// SIZE 0x18
class MxUnknown100d9d00 : public MxList<MxUnknown100d7c88*> {
public:
	MxUnknown100d9d00() { SetDestroy(Destroy); }

	// STUB: LEGO1 0x1007b210
	virtual MxS8 Compare(MxUnknown100d7c88* p_a, MxUnknown100d7c88* p_b) override { return -1; } // vtable+0x14

	// FUNCTION: LEGO1 0x1007b2e0
	static void Destroy(MxUnknown100d7c88* p_element) { delete p_element; }
};

// TEMPLATE: LEGO1 0x1007b300
// MxCollection<MxUnknown100d7c88 *>::Compare

// TEMPLATE: LEGO1 0x1007b360
// MxCollection<MxUnknown100d7c88 *>::Destroy

// SYNTHETIC: LEGO1 0x1007b400
// MxUnknown100d9d00::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1007b470
// MxCollection<MxUnknown100d7c88 *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1007b4e0
// MxList<MxUnknown100d7c88 *>::`scalar deleting destructor'

#endif // MXUNKNOWN100D9D00_H
