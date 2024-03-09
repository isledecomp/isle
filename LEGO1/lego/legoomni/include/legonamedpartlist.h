#ifndef LEGONAMEDPARTLIST_H
#define LEGONAMEDPARTLIST_H

#include "legonamedpart.h"
#include "mxlist.h"

// VTABLE: LEGO1 0x100d9d90
// class MxCollection<LegoNamedPart *>

// VTABLE: LEGO1 0x100d9da8
// class MxList<LegoNamedPart *>

// VTABLE: LEGO1 0x100d9dc0
// class MxPtrList<LegoNamedPart>

// VTABLE: LEGO1 0x100d9dd8
// SIZE 0x18
class LegoNamedPartList : public MxPtrList<LegoNamedPart> {
public:
	LegoNamedPartList() : MxPtrList<LegoNamedPart>(TRUE) {}

	// SYNTHETIC: LEGO1 0x1007dbf0
	// LegoNamedPartList::`scalar deleting destructor'
};

// TEMPLATE: LEGO1 0x1007d760
// MxCollection<LegoNamedPart *>::Compare

// TEMPLATE: LEGO1 0x1007d770
// MxCollection<LegoNamedPart *>::~MxCollection<LegoNamedPart *>

// TEMPLATE: LEGO1 0x1007d7c0
// MxCollection<LegoNamedPart *>::Destroy

// TEMPLATE: LEGO1 0x1007d7d0
// MxList<LegoNamedPart *>::~MxList<LegoNamedPart *>

// TEMPLATE: LEGO1 0x1007d860
// MxPtrList<LegoNamedPart>::Destroy

// TEMPLATE: LEGO1 0x1007dc60
// MxPtrList<LegoNamedPart>::~MxPtrList<LegoNamedPart>

// SYNTHETIC: LEGO1 0x1007dcb0
// MxCollection<LegoNamedPart *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1007dd20
// MxList<LegoNamedPart *>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x1007ddd0
// MxPtrList<LegoNamedPart>::`scalar deleting destructor'

#endif // LEGONAMEDPARTLIST_H
