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

// VTABLE: LEGO1 0x100dcb70
// class MxPtrListCursor<MxRegionTopBottom>

// VTABLE: LEGO1 0x100dcba0
// class MxListCursor<MxRegionTopBottom *>

// TODO: The initialize list param type should be MxRegionList, but doing that
// drastically reduced the match percentage for MxRegion::VTable0x18.
// It also works with MxPtrList, so we'll do that until we figure this out.

// VTABLE: LEGO1 0x100dcb88
class MxRegionListCursor : public MxPtrListCursor<MxRegionTopBottom> {
public:
	MxRegionListCursor(MxPtrList<MxRegionTopBottom>* p_list) : MxPtrListCursor<MxRegionTopBottom>(p_list){};
};

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

// VTABLE: LEGO1 0x100dcbf8
// class MxPtrListCursor<MxRegionLeftRight>

// VTABLE: LEGO1 0x100dcc28
// class MxListCursor<MxRegionLeftRight *>

// VTABLE: LEGO1 0x100dcc10
class MxRegionLeftRightListCursor : public MxPtrListCursor<MxRegionLeftRight> {
public:
	MxRegionLeftRightListCursor(MxRegionLeftRightList* p_list) : MxPtrListCursor<MxRegionLeftRight>(p_list){};
};

#endif // MXREGIONLIST_H
