#ifndef MXREGIONLIST_H
#define MXREGIONLIST_H

#include "mxlist.h"

struct MxRegionTopBottom;
struct MxRegionLeftRight;

// VTABLE 0x100dcb10 TEMPLATE
// class MxCollection<MxRegionTopBottom *>

// VTABLE 0x100dcb28 TEMPLATE
// class MxList<MxRegionTopBottom *>

// VTABLE 0x100dcb40 TEMPLATE
// class MxPtrList<MxRegionTopBottom>

// VTABLE 0x100dcb58
// SIZE 0x18
class MxRegionList : public MxPtrList<MxRegionTopBottom> {
public:
	MxRegionList() : MxPtrList<MxRegionTopBottom>(Destroy) {}
	static void Destroy(MxRegionTopBottom*);
};

// VTABLE 0x100dcb88
typedef MxListCursorChildChild<MxRegionTopBottom*> MxRegionListCursor;

// VTABLE 0x100dcc10
typedef MxListCursorChildChild<MxRegionLeftRight*> MxRegionLeftRightListCursor;

// VTABLE 0x100dcc40 TEMPLATE
// class MxCollection<MxRegionLeftRight *>

// VTABLE 0x100dcc58 TEMPLATE
// class MxList<MxRegionLeftRight *>

// VTABLE 0x100dcc70 TEMPLATE
// class MxPtrList<MxRegionLeftRight>

// VTABLE 0x100dcc88
// SIZE 0x18
class MxRegionLeftRightList : public MxPtrList<MxRegionLeftRight> {
public:
	MxRegionLeftRightList() : MxPtrList<MxRegionLeftRight>(Destroy) {}
	static void Destroy(MxRegionLeftRight*);
};

#endif // MXREGIONLIST_H
