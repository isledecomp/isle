#ifndef LEGOLODLIST_H
#define LEGOLODLIST_H

#include "mxlist.h"
#include "roi/legolod.h"

#pragma warning(disable : 4786)

// VTABLE: LEGO1 0x100d9d30
// class MxCollection<LegoLOD *>

// VTABLE: LEGO1 0x100d9d48
// class MxList<LegoLOD *>

// VTABLE: LEGO1 0x100d9d60
// class MxPtrList<LegoLOD>

// VTABLE: LEGO1 0x100d9d78
// SIZE 0x18
class LegoLODList : public MxPtrList<LegoLOD> {
public:
	LegoLODList() : MxPtrList<LegoLOD>(FALSE) {}

	// SYNTHETIC: LEGO1 0x1007de40
	// LegoLODList::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100d9df0
// class MxListCursor<LegoLOD *>

// VTABLE: LEGO1 0x100d9e08
// class MxPtrListCursor<LegoLOD>

// VTABLE: LEGO1 0x100d9e20
// SIZE 0x10
class LegoLODListCursor : public MxPtrListCursor<LegoLOD> {
public:
	LegoLODListCursor(LegoLODList* p_list) : MxPtrListCursor<LegoLOD>(p_list) {}
};

// SYNTHETIC: LEGO1 0x1007d9b0
// LegoLODListCursor::`scalar deleting destructor'

// FUNCTION: LEGO1 0x1007da20
// MxPtrListCursor<LegoLOD>::~MxPtrListCursor<LegoLOD>

// SYNTHETIC: LEGO1 0x1007da70
// MxListCursor<LegoLOD *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1007dae0
// MxPtrListCursor<LegoLOD>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x1007db50
// MxListCursor<LegoLOD *>::~MxListCursor<LegoLOD *>

// FUNCTION: LEGO1 0x1007dba0
// LegoLODListCursor::~LegoLODListCursor

// TEMPLATE: LEGO1 0x1007d480
// MxCollection<LegoLOD *>::Compare

// TEMPLATE: LEGO1 0x1007d490
// MxCollection<LegoLOD *>::~MxCollection<LegoLOD *>

// TEMPLATE: LEGO1 0x1007d4e0
// MxCollection<LegoLOD *>::Destroy

// TEMPLATE: LEGO1 0x1007d4f0
// MxList<LegoLOD *>::~MxList<LegoLOD *>

// SYNTHETIC: LEGO1 0x1007d580
// MxCollection<LegoLOD *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1007d5f0
// MxList<LegoLOD *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1007d6a0
// MxPtrList<LegoLOD>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x1007d710
// MxPtrList<LegoLOD>::~MxPtrList<LegoLOD>

#endif // LEGOLODLIST_H
