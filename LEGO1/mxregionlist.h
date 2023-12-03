#ifndef MXREGIONLIST_H
#define MXREGIONLIST_H

#include "mxlist.h"

struct MxRegionTopBottom;
struct MxRegionLeftRight;

// VTABLE: LEGO1 0x100dcb10
// class MxCollection<MxRegionTopBottom *>

// VTABLE: LEGO1 0x100dcb28
// class MxList<MxRegionTopBottom *>

// VTABLE: LEGO1 0x100dcb40
// class MxPtrList<MxRegionTopBottom>

// VTABLE: LEGO1 0x100dcb58
// SIZE 0x18
class MxRegionList : public MxPtrList<MxRegionTopBottom> {
public:
	MxRegionList() : MxPtrList<MxRegionTopBottom>(Destroy) {}
	static void Destroy(MxRegionTopBottom*);
};

// VTABLE: LEGO1 0x100dcb88
// class MxListCursorChildChild<MxRegionTopBottom *>
typedef MxListCursorChildChild<MxRegionTopBottom*> MxRegionListCursor;

// VTABLE: LEGO1 0x100dcc10
// class MxListCursorChildChild<MxRegionLeftRight *>
typedef MxListCursorChildChild<MxRegionLeftRight*> MxRegionLeftRightListCursor;

// VTABLE: LEGO1 0x100dcc40
// class MxCollection<MxRegionLeftRight *>

// VTABLE: LEGO1 0x100dcc58
// class MxList<MxRegionLeftRight *>

// VTABLE: LEGO1 0x100dcc70
// class MxPtrList<MxRegionLeftRight>

// VTABLE: LEGO1 0x100dcc88
// SIZE 0x18
class MxRegionLeftRightList : public MxPtrList<MxRegionLeftRight> {
public:
	MxRegionLeftRightList() : MxPtrList<MxRegionLeftRight>(Destroy) {}
	static void Destroy(MxRegionLeftRight*);
};

#endif // MXREGIONLIST_H
