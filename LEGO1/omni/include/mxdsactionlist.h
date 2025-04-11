#ifndef MXDSACTIONLIST_H
#define MXDSACTIONLIST_H

#include "decomp.h"
#include "mxdsaction.h"
#include "mxlist.h"

// VTABLE: LEGO1 0x100dcea8
// VTABLE: BETA10 0x101c2928
// class MxCollection<MxDSAction *>

// VTABLE: LEGO1 0x100dcec0
// VTABLE: BETA10 0x101c2910
// class MxList<MxDSAction *>

// VTABLE: LEGO1 0x100dced8
// VTABLE: BETA10 0x101c28f8
// SIZE 0x1c
class MxDSActionList : public MxList<MxDSAction*> {
public:
	// FUNCTION: BETA10 0x1015ad10
	MxDSActionList() { this->m_unk0x18 = 0; }

	// FUNCTION: LEGO1 0x100c9c90
	// FUNCTION: BETA10 0x1015ad90
	MxS8 Compare(MxDSAction* p_a, MxDSAction* p_b) override
	{
		return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
	} // vtable+0x14

	// FUNCTION: LEGO1 0x100c9cb0
	// FUNCTION: BETA10 0x1015add0
	static void Destroy(MxDSAction* p_action) { delete p_action; }

	// SYNTHETIC: LEGO1 0x100c9dc0
	// SYNTHETIC: BETA10 0x1015b070
	// MxDSActionList::`scalar deleting destructor'

private:
	undefined m_unk0x18; // 0x18
};

// VTABLE: LEGO1 0x100d7e68
// VTABLE: BETA10 0x101baf30
// class MxListCursor<MxDSAction *>

// VTABLE: LEGO1 0x100d7e50
// VTABLE: BETA10 0x101baf18
// SIZE 0x10
class MxDSActionListCursor : public MxListCursor<MxDSAction*> {
public:
	// FUNCTION: BETA10 0x1004db00
	MxDSActionListCursor(MxDSActionList* p_list) : MxListCursor<MxDSAction*>(p_list) {}
};

// TEMPLATE: LEGO1 0x100c9cc0
// TEMPLATE: BETA10 0x1015aed0
// MxCollection<MxDSAction *>::Compare

// TEMPLATE: LEGO1 0x100c9cd0
// TEMPLATE: BETA10 0x1015af80
// MxCollection<MxDSAction *>::~MxCollection<MxDSAction *>

// TEMPLATE: LEGO1 0x100c9d20
// TEMPLATE: BETA10 0x1015aff0
// MxCollection<MxDSAction *>::Destroy

// TEMPLATE: LEGO1 0x100c9d30
// TEMPLATE: BETA10 0x1015b000
// MxList<MxDSAction *>::~MxList<MxDSAction *>

// SYNTHETIC: LEGO1 0x100c9e30
// SYNTHETIC: BETA10 0x1015b0b0
// MxCollection<MxDSAction *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100c9ea0
// SYNTHETIC: BETA10 0x1015b0f0
// MxList<MxDSAction *>::`scalar deleting destructor'

// TEMPLATE: BETA10 0x1004dba0
// MxListCursor<MxDSAction *>::MxListCursor<MxDSAction *>

// TEMPLATE: BETA10 0x1004e460
// MxListCursor<MxDSAction *>::Head

// TEMPLATE: BETA10 0x1004e4b0
// ?Next@?$MxListCursor@PAVMxDSAction@@@@QAEEXZ

// TEMPLATE: BETA10 0x1004e530
// MxListCursor<MxDSAction *>::Current

// TEMPLATE: BETA10 0x1004e590
// MxListEntry<MxDSAction *>::GetNext

// TEMPLATE: BETA10 0x1004e5c0
// MxListEntry<MxDSAction *>::GetValue

// TEMPLATE: BETA10 0x10137190
// ?Next@?$MxListCursor@PAVMxDSAction@@@@QAEEAAPAVMxDSAction@@@Z

// TEMPLATE: BETA10 0x101384e0
// MxListCursor<MxDSAction *>::Find

// TEMPLATE: BETA10 0x10138580
// MxListCursor<MxDSAction *>::Detach

// TEMPLATE: BETA10 0x101385c0
// MxList<MxDSAction *>::DeleteEntry

// TEMPLATE: BETA10 0x10138670
// MxListEntry<MxDSAction *>::GetPrev

// TEMPLATE: BETA10 0x10138690
// MxListEntry<MxDSAction *>::SetPrev

// TEMPLATE: BETA10 0x101386c0
// MxListEntry<MxDSAction *>::SetNext

// TEMPLATE: BETA10 0x1015ae10
// MxCollection<MxDSAction *>::SetDestroy

// TEMPLATE: BETA10 0x1015ae40
// MxList<MxDSAction *>::MxList<MxDSAction *>

// TEMPLATE: BETA10 0x1015aef0
// MxCollection<MxDSAction *>::MxCollection<MxDSAction *>

// SYNTHETIC: BETA10 0x1015b130
// MxDSActionList::~MxDSActionList

// TEMPLATE: BETA10 0x1015b250
// MxList<MxDSAction *>::Append

// TEMPLATE: BETA10 0x1015bca0
// MxList<MxDSAction *>::InsertEntry

// TEMPLATE: BETA10 0x1015c140
// MxListEntry<MxDSAction *>::MxListEntry<MxDSAction *>

// TEMPLATE: BETA10 0x1015bd90
// MxList<MxDSAction *>::DeleteAll

// TEMPLATE: BETA10 0x1015be20
// MxListCursor<MxDSAction *>::HasMatch

#endif // MXDSACTIONLIST_H
