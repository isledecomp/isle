#ifndef LEGOROILIST_H
#define LEGOROILIST_H

#include "mxlist.h"
#include "mxtypes.h"
#include "roi/legoroi.h"

// VTABLE: LEGO1 0x100d8c30
// class MxCollection<LegoROI *>

// VTABLE: LEGO1 0x100d8c48
// class MxList<LegoROI *>

// VTABLE: LEGO1 0x100d8c60
// class MxPtrList<LegoROI>

// VTABLE: LEGO1 0x100d8c78
// SIZE 0x18
class LegoROIList : public MxPtrList<LegoROI> {
public:
	LegoROIList(MxBool p_ownership = FALSE) : MxPtrList<LegoROI>(p_ownership) {}

	// FUNCTION: LEGO1 0x1005f360
	MxS8 Compare(LegoROI* p_a, LegoROI* p_b) override { return p_a == p_b ? 0 : p_a < p_b ? -1 : 1; } // vtable+0x14

	// SYNTHETIC: LEGO1 0x1005f480
	// LegoROIList::`scalar deleting destructor'
};

// TEMPLATE: LEGO1 0x1005f380
// MxCollection<LegoROI *>::Compare

// TEMPLATE: LEGO1 0x1005f390
// MxCollection<LegoROI *>::~MxCollection<LegoROI *>

// TEMPLATE: LEGO1 0x1005f3e0
// MxCollection<LegoROI *>::Destroy

// TEMPLATE: LEGO1 0x1005f3f0
// MxList<LegoROI *>::~MxList<LegoROI *>

// TEMPLATE: LEGO1 0x1005f4f0
// MxPtrList<LegoROI>::~MxPtrList<LegoROI>

// SYNTHETIC: LEGO1 0x1005f540
// MxCollection<LegoROI *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1005f5b0
// MxList<LegoROI *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1005f660
// MxPtrList<LegoROI>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1006ea00
// MxListEntry<LegoROI *>::MxListEntry<LegoROI *>

#endif // LEGOROILIST_H
