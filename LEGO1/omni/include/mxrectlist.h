#ifndef MXRECTLIST_H
#define MXRECTLIST_H

#include "mxlist.h"
#include "mxrect32.h"

// VTABLE: LEGO1 0x100dc3f0
// VTABLE: BETA10 0x101c1fb8
// SIZE 0x18
class MxRectList : public MxPtrList<MxRect32> {
public:
	// FUNCTION: BETA10 0x1013b980
	MxRectList(MxBool p_ownership = FALSE) : MxPtrList<MxRect32>(p_ownership) {}
};

// VTABLE: LEGO1 0x100dc438
// VTABLE: BETA10 0x101c2048
// class MxListCursor<MxRect32 *>

// VTABLE: LEGO1 0x100dc408
// VTABLE: BETA10 0x101c2030
// class MxPtrListCursor<MxRect32>

// VTABLE: LEGO1 0x100dc420
// VTABLE: BETA10 0x101c2018
class MxRectListCursor : public MxPtrListCursor<MxRect32> {
public:
	// FUNCTION: BETA10 0x1013bf10
	MxRectListCursor(MxRectList* p_list) : MxPtrListCursor<MxRect32>(p_list) {}
};

// VTABLE: LEGO1 0x100dc3d8
// VTABLE: BETA10 0x101c1fd0
// class MxPtrList<MxRect32>

// VTABLE: LEGO1 0x100dc450
// VTABLE: BETA10 0x101c1fe8
// class MxList<MxRect32 *>

// VTABLE: LEGO1 0x100dc468
// VTABLE: BETA10 0x101c2000
// class MxCollection<MxRect32 *>

// TEMPLATE: LEGO1 0x100b3c00
// TEMPLATE: BETA10 0x1013ba00
// MxCollection<MxRect32 *>::Compare

// TEMPLATE: LEGO1 0x100b3c10
// TEMPLATE: BETA10 0x1013bb30
// MxCollection<MxRect32 *>::MxCollection<MxRect32 *>

// TEMPLATE: LEGO1 0x100b3c80
// TEMPLATE: BETA10 0x1013bbc0
// MxCollection<MxRect32 *>::~MxCollection<MxRect32 *>

// TEMPLATE: LEGO1 0x100b3cd0
// TEMPLATE: BETA10 0x1013bc60
// MxCollection<MxRect32 *>::Destroy

// TEMPLATE: LEGO1 0x100b3ce0
// TEMPLATE: BETA10 0x1013bc70
// MxList<MxRect32 *>::~MxList<MxRect32 *>

// TEMPLATE: LEGO1 0x100b3d70
// TEMPLATE: BETA10 0x1013bd20
// MxPtrList<MxRect32>::Destroy

// SYNTHETIC: LEGO1 0x100b3d80
// SYNTHETIC: BETA10 0x1013bd50
// MxRectList::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100b3df0
// TEMPLATE: BETA10 0x1013bd90
// MxPtrList<MxRect32>::~MxPtrList<MxRect32>

// SYNTHETIC: LEGO1 0x100b3e40
// SYNTHETIC: BETA10 0x1013bdf0
// MxCollection<MxRect32 *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100b3eb0
// SYNTHETIC: BETA10 0x1013be30
// MxList<MxRect32 *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100b3f60
// SYNTHETIC: BETA10 0x1013be70
// MxPtrList<MxRect32>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100b3fd0
// SYNTHETIC: BETA10 0x1013beb0
// MxRectList::~MxRectList

// SYNTHETIC: LEGO1 0x100b4020
// SYNTHETIC: BETA10 0x1013c0a0
// MxRectListCursor::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100b4090
// TEMPLATE: BETA10 0x1013c0e0
// MxPtrListCursor<MxRect32>::~MxPtrListCursor<MxRect32>

// SYNTHETIC: LEGO1 0x100b40e0
// SYNTHETIC: BETA10 0x1013c140
// MxListCursor<MxRect32 *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100b4150
// SYNTHETIC: BETA10 0x1013c180
// MxPtrListCursor<MxRect32>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100b41c0
// TEMPLATE: BETA10 0x1013c1c0
// MxListCursor<MxRect32 *>::~MxListCursor<MxRect32 *>

// SYNTHETIC: LEGO1 0x100b4210
// SYNTHETIC: BETA10 0x1013c220
// MxRectListCursor::~MxRectListCursor

// TEMPLATE: BETA10 0x1013ba20
// MxPtrList<MxRect32>::MxPtrList<MxRect32>

// TEMPLATE: BETA10 0x1013baa0
// MxList<MxRect32 *>::MxList<MxRect32 *>

// TEMPLATE: BETA10 0x1013bc30
// MxCollection<MxRect32 *>::SetDestroy

// TEMPLATE: BETA10 0x1013bce0
// MxPtrList<MxRect32>::SetOwnership

// TEMPLATE: BETA10 0x1013bf90
// MxPtrListCursor<MxRect32>::MxPtrListCursor<MxRect32>

// TEMPLATE: BETA10 0x1013c010
// MxListCursor<MxRect32 *>::MxListCursor<MxRect32 *>

// TEMPLATE: BETA10 0x1013c3c0
// MxList<MxRect32 *>::DeleteAll

// TEMPLATE: BETA10 0x1013c450
// MxListCursor<MxRect32 *>::Next

// TEMPLATE: BETA10 0x1013c610
// MxListEntry<MxRect32 *>::GetNext

// TEMPLATE: BETA10 0x1013c630
// MxListEntry<MxRect32 *>::GetValue

// TEMPLATE: BETA10 0x10152860
// MxList<MxRect32 *>::Append

// TEMPLATE: BETA10 0x10152890
// MxList<MxRect32 *>::InsertEntry

// TEMPLATE: BETA10 0x10152980
// MxListEntry<MxRect32 *>::MxListEntry<MxRect32 *>

// TEMPLATE: BETA10 0x101529c0
// MxListEntry<MxRect32 *>::SetPrev

// TEMPLATE: BETA10 0x101529f0
// MxListEntry<MxRect32 *>::SetNext

#endif // MXRECTLIST_H
