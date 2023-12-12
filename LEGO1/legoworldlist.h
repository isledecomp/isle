#ifndef LEGOWORLDLIST_H
#define LEGOWORLDLIST_H

#include "mxlist.h"
#include "mxtypes.h"

class LegoWorld;

// VTABLE: LEGO1 0x100d8700
// class MxCollection<LegoWorld *>

// VTABLE: LEGO1 0x100d8718
// class MxList<LegoWorld *>

// VTABLE: LEGO1 0x100d8730
// class MxPtrList<LegoWorld>

// VTABLE: LEGO1 0x100d8680
// SIZE 0x18
class LegoWorldList : public MxPtrList<LegoWorld> {
public:
	LegoWorldList() : MxPtrList<LegoWorld>(Destroy) {}
	virtual MxS8 Compare(LegoWorld*, LegoWorld*) override; // vtable+0x14
	static void Destroy(LegoWorld*);
};

// TEMPLATE: LEGO1 0x100598f0
// MxCollection<LegoWorld *>::Compare

// TEMPLATE: LEGO1 0x10059900
// MxCollection<LegoWorld *>::~MxCollection<LegoWorld *>

// TEMPLATE: LEGO1 0x10059950
// MxCollection<LegoWorld *>::Destroy

// TEMPLATE: LEGO1 0x10059960
// MxList<LegoWorld *>::~MxList<LegoWorld *>

// SYNTHETIC: LEGO1 0x10059ac0
// MxCollection<LegoWorld *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x10059b30
// MxList<LegoWorld *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x10059be0
// MxPtrList<LegoWorld>::`scalar deleting destructor'

#endif // LEGOWORLDLIST_H
