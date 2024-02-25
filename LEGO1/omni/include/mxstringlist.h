#ifndef MXSTRINGLIST_H
#define MXSTRINGLIST_H

#include "mxlist.h"
#include "mxstring.h"

// VTABLE: LEGO1 0x100dd040
// SIZE 0x18
class MxStringList : public MxList<MxString> {};

// VTABLE: LEGO1 0x100dd058
// SIZE 0x10
class MxStringListCursor : public MxListCursor<MxString> {
public:
	MxStringListCursor(MxStringList* p_list) : MxListCursor<MxString>(p_list) {}

	// SYNTHETIC: LEGO1 0x100cb860
	// MxStringList::`scalar deleting destructor'
};

// VTABLE: LEGO1 0x100dd010
// class MxCollection<MxString>

// VTABLE: LEGO1 0x100dd028
// class MxList<MxString>

// VTABLE: LEGO1 0x100dd070
// class MxListCursor<MxString>

// TEMPLATE: LEGO1 0x100cb3c0
// MxCollection<MxString>::Compare

// TEMPLATE: LEGO1 0x100cb420
// MxCollection<MxString>::~MxCollection<MxString>

// TEMPLATE: LEGO1 0x100cb470
// MxCollection<MxString>::Destroy

// TEMPLATE: LEGO1 0x100cb4c0
// MxList<MxString>::~MxList<MxString>

// SYNTHETIC: LEGO1 0x100cb590
// MxCollection<MxString>::`scalar deleting destructor'

// SYNTHETIC: LEGO1 0x100cb600
// MxList<MxString>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100cbb40
// MxList<MxString>::Append

// TEMPLATE: LEGO1 0x100cc2d0
// MxList<MxString>::InsertEntry

// TEMPLATE: LEGO1 0x100cc3c0
// MxListEntry<MxString>::MxListEntry<MxString>

// TEMPLATE: LEGO1 0x100cc450
// MxListEntry<MxString>::GetValue

#endif // MXSTRINGLIST_H
