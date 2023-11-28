#ifndef MXREGIONLIST_H
#define MXREGIONLIST_H

#include "mxlist.h"

struct MxRegionTopBottom;
struct MxRegionLeftRight;

// VTABLE: LEGO1 0x100dcb10 SYNTHETIC
// class MxCollection<MxRegionTopBottom *>

// VTABLE: LEGO1 0x100dcb28 SYNTHETIC
// class MxList<MxRegionTopBottom *>

// VTABLE: LEGO1 0x100dcb40 SYNTHETIC
// class MxPtrList<MxRegionTopBottom>

// VTABLE: LEGO1 0x100dcb58
// SIZE 0x18
class MxRegionList : public MxPtrList<MxRegionTopBottom> {
public:
	MxRegionList() : MxPtrList<MxRegionTopBottom>(Destroy) {}
	static void Destroy(MxRegionTopBottom*);
};

// VTABLE: LEGO1 0x100dcb88
typedef MxListCursorChildChild<MxRegionTopBottom*> MxRegionListCursor;

// VTABLE: LEGO1 0x100dcc10
typedef MxListCursorChildChild<MxRegionLeftRight*> MxRegionLeftRightListCursor;

// VTABLE: LEGO1 0x100dcc40 SYNTHETIC
// class MxCollection<MxRegionLeftRight *>

// VTABLE: LEGO1 0x100dcc58 SYNTHETIC
// class MxList<MxRegionLeftRight *>

// VTABLE: LEGO1 0x100dcc70 SYNTHETIC
// class MxPtrList<MxRegionLeftRight>

// VTABLE: LEGO1 0x100dcc88
// SIZE 0x18
class MxRegionLeftRightList : public MxPtrList<MxRegionLeftRight> {
public:
	MxRegionLeftRightList() : MxPtrList<MxRegionLeftRight>(Destroy) {}
	static void Destroy(MxRegionLeftRight*);
};

#endif // MXREGIONLIST_H
