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
	MxDSActionList() { this->m_unk18 = 0; }

	virtual MxS8 Compare(MxDSAction*, MxDSAction*) override; // vtable+0x14

	static void Destroy(MxDSAction* p_action);

private:
	undefined m_unk18;
};

class MxDSActionListCursor : public MxListCursor<MxDSAction*> {
public:
	MxDSActionListCursor(MxDSActionList* p_list) : MxListCursor<MxDSAction*>(p_list){};
};

#endif // MXDSACTIONLIST_H
