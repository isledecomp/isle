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

#endif // LEGOWORLDLIST_H
