#ifndef MXSTRINGLIST_H
#define MXSTRINGLIST_H

#include "mxlist.h"
#include "mxstring.h"

// VTABLE 0x100dd040
// SIZE 0x18
class MxStringList : public MxList<MxString> {};

// OFFSET: LEGO1 0x100cb3c0 TEMPLATE
// MxListParent<MxString>::Compare

// OFFSET: LEGO1 0x100cb470 TEMPLATE
// MxListParent<MxString>::Destroy

// OFFSET: LEGO1 0x100cb4c0 TEMPLATE
// MxList<MxString>::~MxList<MxString>

// OFFSET: LEGO1 0x100cc450 TEMPLATE
// MxListEntry<MxString>::GetValue

#endif // MXSTRINGLIST_H
