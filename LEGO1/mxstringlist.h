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

#endif // MXSTRINGLIST_H
