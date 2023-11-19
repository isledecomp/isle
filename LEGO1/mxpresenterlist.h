#ifndef MXPRESENTERLIST_H
#define MXPRESENTERLIST_H

#include "mxlist.h"

class MxPresenter;

// VTABLE 0x100d62f0 TEMPLATE
// class MxPtrList<MxPresenter>

// VTABLE 0x100d6308
// SIZE 0x18
class MxPresenterList : public MxPtrList<MxPresenter> {
public:
	virtual MxS8 Compare(MxPresenter*, MxPresenter*) override; // vtable+0x14
};

typedef MxListCursorChildChild<MxPresenter*> MxPresenterListCursor;

// VTABLE 0x100d6350 TEMPLATE
// class MxCollection<MxPresenter *>

// VTABLE 0x100d6368 TEMPLATE
// class MxList<MxPresenter *>

#endif // MXPRESENTERLIST_H
