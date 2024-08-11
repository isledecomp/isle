#ifndef MXSTRINGLIST_H
#define MXSTRINGLIST_H

#include "mxlist.h"
#include "mxstring.h"

// VTABLE: LEGO1 0x100dd040
// VTABLE: BETA10 0x101c2a18
// SIZE 0x18
class MxStringList : public MxList<MxString> {};

// SYNTHETIC: BETA10 0x1015b520
// MxStringList::MxStringList

// SYNTHETIC: LEGO1 0x100cb860
// SYNTHETIC: BETA10 0x1015b920
// MxStringList::`scalar deleting destructor'

// SYNTHETIC: BETA10 0x1015b960
// MxStringList::~MxStringList

// VTABLE: LEGO1 0x100dd058
// VTABLE: BETA10 0x101c2a60
// SIZE 0x10
class MxStringListCursor : public MxListCursor<MxString> {
public:
	// FUNCTION: BETA10 0x1015ba50
	MxStringListCursor(MxStringList* p_list) : MxListCursor<MxString>(p_list) {}
};

// VTABLE: LEGO1 0x100dd010
// VTABLE: BETA10 0x101c2a48
// class MxCollection<MxString>

// VTABLE: LEGO1 0x100dd028
// VTABLE: BETA10 0x101c2a30
// class MxList<MxString>

// VTABLE: LEGO1 0x100dd070
// VTABLE: BETA10 0x101c2a78
// class MxListCursor<MxString>

// TEMPLATE: LEGO1 0x100cb3c0
// TEMPLATE: BETA10 0x1015b590
// MxCollection<MxString>::Compare

// TEMPLATE: LEGO1 0x100cb420
// TEMPLATE: BETA10 0x1015b730
// MxCollection<MxString>::~MxCollection<MxString>

// TEMPLATE: LEGO1 0x100cb470
// TEMPLATE: BETA10 0x1015b7d0
// MxCollection<MxString>::Destroy

// TEMPLATE: LEGO1 0x100cb4c0
// TEMPLATE: BETA10 0x1015b830
// MxList<MxString>::~MxList<MxString>

// SYNTHETIC: LEGO1 0x100cb590
// SYNTHETIC: BETA10 0x1015b8a0
// MxCollection<MxString>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100cb600
// SYNTHETIC: BETA10 0x1015b8e0
// MxList<MxString>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100cbb40
// TEMPLATE: BETA10 0x1015b9c0
// MxList<MxString>::Append

// TEMPLATE: LEGO1 0x100cc2d0
// TEMPLATE: BETA10 0x1015be50
// MxList<MxString>::InsertEntry

// TEMPLATE: LEGO1 0x100cc3c0
// TEMPLATE: BETA10 0x1015c180
// MxListEntry<MxString>::MxListEntry<MxString>

// TEMPLATE: LEGO1 0x100cc450
// TEMPLATE: BETA10 0x1015c2a0
// MxListEntry<MxString>::GetValue

// TEMPLATE: BETA10 0x1015b610
// MxList<MxString>::MxList<MxString>

// TEMPLATE: BETA10 0x1015b6a0
// MxCollection<MxString>::MxCollection<MxString>

// TEMPLATE: BETA10 0x1015b7a0
// MxCollection<MxString>::SetDestroy

// TEMPLATE: BETA10 0x1015bad0
// MxListCursor<MxString>::MxListCursor<MxString>

// TEMPLATE: BETA10 0x1015bf80
// MxList<MxString>::DeleteAll

// TEMPLATE: BETA10 0x1015c070
// MxListCursor<MxString>::Next

// TEMPLATE: BETA10 0x1015c220
// MxListEntry<MxString>::SetPrev

// TEMPLATE: BETA10 0x1015c250
// MxListEntry<MxString>::GetNext

// TEMPLATE: BETA10 0x1015c270
// MxListEntry<MxString>::SetNext

// SYNTHETIC: BETA10 0x1015c310
// MxListEntry<MxString>::`scalar deleting destructor'

// TEMPLATE: BETA10 0x1015c350
// MxListEntry<MxString>::~MxListEntry<MxString>

#endif // MXSTRINGLIST_H
