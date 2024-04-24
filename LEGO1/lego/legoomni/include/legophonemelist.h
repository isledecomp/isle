#ifndef LEGOPHONEMELIST_H
#define LEGOPHONEMELIST_H

#include "decomp.h"
#include "legophoneme.h"
#include "mxlist.h"

// VTABLE: LEGO1 0x100d9cd0
// class MxCollection<LegoPhoneme *>

// VTABLE: LEGO1 0x100d9ce8
// class MxList<LegoPhoneme *>

// VTABLE: LEGO1 0x100d9d00
// VTABLE: BETA10 0x101bef58
// SIZE 0x18
class LegoPhonemeList : public MxList<LegoPhoneme*> {
public:
	LegoPhonemeList() { SetDestroy(Destroy); }

	// FUNCTION: LEGO1 0x1007b210
	// FUNCTION: BETA10 0x100d8340
	MxS8 Compare(LegoPhoneme* p_a, LegoPhoneme* p_b) override
	{
		MxString a(p_a->GetName());
		MxString b(p_b->GetName());
		return a.Equal(b) ? 0 : p_a < p_b ? -1 : 1;
	} // vtable+0x14

	// FUNCTION: LEGO1 0x1007b2e0
	static void Destroy(LegoPhoneme* p_element) { delete p_element; }
};

// VTABLE: LEGO1 0x100d80c8
// class MxListCursor<LegoPhoneme *>

// VTABLE: LEGO1 0x100d80e0
// SIZE 0x10
class LegoPhonemeListCursor : public MxListCursor<LegoPhoneme*> {
public:
	LegoPhonemeListCursor(LegoPhonemeList* p_list) : MxListCursor<LegoPhoneme*>(p_list) {}
};

// TEMPLATE: LEGO1 0x1004e680
// LegoPhonemeListCursor::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1004e6f0
// MxListCursor<LegoPhoneme *>::~MxListCursor<LegoPhoneme *>

// TEMPLATE: LEGO1 0x1004e740
// MxListCursor<LegoPhoneme *>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1004e7b0
// LegoPhonemeListCursor::~LegoPhonemeListCursor

// TEMPLATE: LEGO1 0x1007b300
// MxCollection<LegoPhoneme *>::Compare

// TEMPLATE: LEGO1 0x1007b310
// MxCollection<LegoPhoneme *>::~MxCollection<LegoPhoneme *>

// TEMPLATE: LEGO1 0x1007b360
// MxCollection<LegoPhoneme *>::Destroy

// TEMPLATE: LEGO1 0x1007b370
// MxList<LegoPhoneme *>::~MxList<LegoPhoneme *>

// SYNTHETIC: LEGO1 0x1007b400
// LegoPhonemeList::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1007b470
// MxCollection<LegoPhoneme *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1007b4e0
// MxList<LegoPhoneme *>::`scalar deleting destructor'

#endif // LEGOPHONEMELIST_H
