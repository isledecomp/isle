#ifndef MXSTRINGLIST_H
#define MXSTRINGLIST_H

#include "mxlist.h"
#include "mxstring.h"

// VTABLE: LEGO1 0x100dd040
// SIZE 0x18
class MxStringList : public MxList<MxString> {};

// VTABLE: LEGO1 0x100dd058
class MxStringListCursor : public MxListCursor<MxString> {
public:
	MxStringListCursor(MxStringList* p_list) : MxListCursor<MxString>(p_list){};
};

// VTABLE: LEGO1 0x100dd070
// class MxListCursor<MxString>

// TEMPLATE: LEGO1 0x100cb3c0
// MxCollection<MxString>::Compare

// TEMPLATE: LEGO1 0x100cb470
// MxCollection<MxString>::Destroy

// TEMPLATE: LEGO1 0x100cb4c0
// MxList<MxString>::~MxList<MxString>

// TEMPLATE: LEGO1 0x100cbb40
// MxList<MxString>::Append

// TEMPLATE: LEGO1 0x100cc2d0
// MxList<MxString>::InsertEntry

// TEMPLATE: LEGO1 0x100cc3c0
// MxListEntry<MxString>::MxListEntry<MxString>

// TEMPLATE: LEGO1 0x100cc450
// MxListEntry<MxString>::GetValue

#endif // MXSTRINGLIST_H
