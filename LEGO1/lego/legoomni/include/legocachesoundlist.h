#ifndef LEGOCACHESOUNDLIST_H
#define LEGOCACHESOUNDLIST_H

#include "mxlist.h"
#include "mxtypes.h"

class LegoCacheSound;

// VTABLE: LEGO1 0x100d63b0
// class MxCollection<LegoCacheSound *>

// VTABLE: LEGO1 0x100d63c8
// class MxList<LegoCacheSound *>

// VTABLE: LEGO1 0x100d63e0
// class MxPtrList<LegoCacheSound>

// VTABLE: LEGO1 0x100d63f8
// SIZE 0x18
class LegoCacheSoundList : public MxPtrList<LegoCacheSound> {
public:
	LegoCacheSoundList(MxBool p_ownership = FALSE) : MxPtrList<LegoCacheSound>(p_ownership) {}

	// FUNCTION: LEGO1 0x1001e650
	MxS8 Compare(LegoCacheSound* p_a, LegoCacheSound* p_b) override
	{
		return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
	} // vtable+0x14
};

// VTABLE: LEGO1 0x100d64a0
// class MxListCursor<LegoCacheSound *>

// VTABLE: LEGO1 0x100d6500
// class MxPtrListCursor<LegoCacheSound>

// VTABLE: LEGO1 0x100d6518
// SIZE 0x10
class LegoCacheSoundListCursor : public MxPtrListCursor<LegoCacheSound> {
public:
	LegoCacheSoundListCursor(LegoCacheSoundList* p_list) : MxPtrListCursor<LegoCacheSound>(p_list) {}
};

// TEMPLATE: LEGO1 0x1001e670
// MxCollection<LegoCacheSound *>::Compare

// TEMPLATE: LEGO1 0x1001e680
// MxCollection<LegoCacheSound *>::~MxCollection<LegoCacheSound *>

// TEMPLATE: LEGO1 0x1001e6d0
// MxCollection<LegoCacheSound *>::Destroy

// TEMPLATE: LEGO1 0x1001e6e0
// MxList<LegoCacheSound *>::~MxList<LegoCacheSound *>

// TEMPLATE: LEGO1 0x1001e770
// MxPtrList<LegoCacheSound>::Destroy

// SYNTHETIC: LEGO1 0x1001e780
// LegoCacheSoundList::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1001e7f0
// MxPtrList<LegoCacheSound>::~MxPtrList<LegoCacheSound>

// SYNTHETIC: LEGO1 0x1001e840
// MxCollection<LegoCacheSound *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001e8b0
// MxList<LegoCacheSound *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001e960
// MxPtrList<LegoCacheSound>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001f350
// LegoCacheSoundListCursor::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1001f3c0
// MxPtrListCursor<LegoCacheSound>::~MxPtrListCursor<LegoCacheSound>

// SYNTHETIC: LEGO1 0x1001f410
// MxListCursor<LegoCacheSound *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1001f480
// MxPtrListCursor<LegoCacheSound>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1001f4f0
// MxListCursor<LegoCacheSound *>::~MxListCursor<LegoCacheSound *>

// FUNCTION: LEGO1 0x1001f540
// LegoCacheSoundListCursor::~LegoCacheSoundListCursor

// TEMPLATE: LEGO1 0x10020840
// MxListCursor<LegoCacheSound *>::MxListCursor<LegoCacheSound *>

// TEMPLATE: LEGO1 0x100224e0
// MxList<LegoCacheSound *>::InsertEntry

// TEMPLATE: LEGO1 0x10022590
// MxListCursor<LegoCacheSound *>::Find

// TEMPLATE: LEGO1 0x10022680
// MxList<LegoCacheSound *>::DeleteEntry

#endif // LEGOCACHESOUNDLIST_H
