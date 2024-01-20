#ifndef MXDSACTIONLIST_H
#define MXDSACTIONLIST_H

#include "decomp.h"
#include "mxlist.h"

class MxDSAction;

// VTABLE: LEGO1 0x100dcea8
// class MxCollection<MxDSAction *>

// VTABLE: LEGO1 0x100dcec0
// class MxList<MxDSAction *>

// VTABLE: LEGO1 0x100dced8
// SIZE 0x1c
class MxDSActionList : public MxList<MxDSAction*> {
public:
	MxDSActionList() { this->m_unk0x18 = 0; }

	// FUNCTION: LEGO1 0x100c9c90
	virtual MxS8 Compare(MxDSAction* p_a, MxDSAction* p_b) override
	{
		return p_a == p_b ? 0 : p_a < p_b ? -1 : 1;
	} // vtable+0x14

	// FUNCTION: LEGO1 0x100c9cb0
	static void Destroy(MxDSAction* p_action) { delete p_action; }

	// SYNTHETIC: LEGO1 0x100c9dc0
	// MxDSActionList::`scalar deleting destructor'

private:
	undefined m_unk0x18;
};

// VTABLE: LEGO1 0x100d7e68
// class MxListCursor<MxDSAction *>

// VTABLE: LEGO1 0x100d7e50
// SIZE 0x10
class MxDSActionListCursor : public MxListCursor<MxDSAction*> {
public:
	MxDSActionListCursor(MxDSActionList* p_list) : MxListCursor<MxDSAction*>(p_list){};
};

// TEMPLATE: LEGO1 0x100c9cc0
// MxCollection<MxDSAction *>::Compare

// TEMPLATE: LEGO1 0x100c9cd0
// MxCollection<MxDSAction *>::~MxCollection<MxDSAction *>

// TEMPLATE: LEGO1 0x100c9d20
// MxCollection<MxDSAction *>::Destroy

// TEMPLATE: LEGO1 0x100c9d30
// MxList<MxDSAction *>::~MxList<MxDSAction *>

// SYNTHETIC: LEGO1 0x100c9e30
// MxCollection<MxDSAction *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100c9ea0
// MxList<MxDSAction *>::`scalar deleting destructor'

#endif // MXDSACTIONLIST_H
