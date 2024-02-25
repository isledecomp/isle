#ifndef MXRECTLIST_H
#define MXRECTLIST_H

#include "mxlist.h"
#include "mxrect32.h"

// VTABLE: LEGO1 0x100dc3f0
// SIZE 0x18
class MxRectList : public MxPtrList<MxRect32> {
public:
	MxRectList(MxBool p_ownership = FALSE) : MxPtrList<MxRect32>(p_ownership) {}
};

// VTABLE: LEGO1 0x100dc438
// class MxListCursor<MxRect32 *>

// VTABLE: LEGO1 0x100dc408
// class MxPtrListCursor<MxRect32>

// VTABLE: LEGO1 0x100dc420
class MxRectListCursor : public MxPtrListCursor<MxRect32> {
public:
	MxRectListCursor(MxRectList* p_list) : MxPtrListCursor<MxRect32>(p_list) {}
};

// VTABLE: LEGO1 0x100dc3d8
// class MxPtrList<MxRect32>

// VTABLE: LEGO1 0x100dc450
// class MxList<MxRect32 *>

// VTABLE: LEGO1 0x100dc468
// class MxCollection<MxRect32 *>

// TEMPLATE: LEGO1 0x100b3c00
// MxCollection<MxRect32 *>::Compare

// TEMPLATE: LEGO1 0x100b3c10
// MxCollection<MxRect32 *>::MxCollection<MxRect32 *>

// TEMPLATE: LEGO1 0x100b3c80
// MxCollection<MxRect32 *>::~MxCollection<MxRect32 *>

// TEMPLATE: LEGO1 0x100b3cd0
// MxCollection<MxRect32 *>::Destroy

// TEMPLATE: LEGO1 0x100b3ce0
// MxList<MxRect32 *>::~MxList<MxRect32 *>

// TEMPLATE: LEGO1 0x100b3d70
// MxPtrList<MxRect32>::Destroy

// SYNTHETIC: LEGO1 0x100b3d80
// MxRectList::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100b3df0
// MxPtrList<MxRect32>::~MxPtrList<MxRect32>

// SYNTHETIC: LEGO1 0x100b3e40
// MxCollection<MxRect32 *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100b3eb0
// MxList<MxRect32 *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100b3f60
// MxPtrList<MxRect32>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100b3fd0
// MxRectList::~MxRectList

// SYNTHETIC: LEGO1 0x100b4020
// MxRectListCursor::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100b4090
// MxPtrListCursor<MxRect32>::~MxPtrListCursor<MxRect32>

// SYNTHETIC: LEGO1 0x100b40e0
// MxListCursor<MxRect32 *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100b4150
// MxPtrListCursor<MxRect32>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100b41c0
// MxListCursor<MxRect32 *>::~MxListCursor<MxRect32 *>

// TEMPLATE: LEGO1 0x100b4210
// MxRectListCursor::~MxRectListCursor

#endif // MXRECTLIST_H
