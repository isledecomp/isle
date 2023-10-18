#ifndef MXREGIONLIST_H
#define MXREGIONLIST_H

#include "mxlist.h"

struct MxRegionTopBottom;
struct MxRegionLeftRight;

// VTABLE 0x100dcb40
// SIZE 0x18
class MxRegionListParent : public MxList<MxRegionTopBottom*>
{
public:
  static void Destroy(MxRegionTopBottom *p_topBottom);

  MxRegionListParent() {
    m_customDestructor = Destroy;
  }
};

// VTABLE 0x100dcb58
// SIZE 0x18
class MxRegionList : public MxRegionListParent {};

// VTABLE 0x100dcb88
typedef MxListCursorChildChild<MxRegionTopBottom*> MxRegionListCursor;

// OFFSET: LEGO1 0x100c5970 TEMPLATE
// MxList<MxRegionTopBottom *>::_InsertEntry

// OFFSET: LEGO1 0x100c5a20 TEMPLATE
// MxListEntry<MxRegionTopBottom *>::MxListEntry<MxRegionTopBottom *>

// VTABLE 0x100dcc70
// SIZE 0x18
class MxRegionLeftRightListParent : public MxList<MxRegionLeftRight*>
{
public:
  static void Destroy(MxRegionLeftRight *p_leftRight);

  MxRegionLeftRightListParent() {
    m_customDestructor = Destroy;
  }
};

// VTABLE 0x100dcc88
// SIZE 0x18
class MxRegionLeftRightList : public MxRegionLeftRightListParent {};

#endif // MXREGIONLIST_H
