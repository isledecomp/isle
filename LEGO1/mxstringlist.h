#ifndef MXSTRINGLIST_H
#define MXSTRINGLIST_H

#include "mxlist.h"
#include "mxstring.h"

// VTABLE 0x100dd040
// SIZE 0x18
class MxStringList : public MxList<MxString> {};

// VTABLE 0x100dd058
typedef MxListCursorChild<MxString> MxStringListCursor;

#endif // MXSTRINGLIST_H
