#ifndef MXPRESENTERLIST_H
#define MXPRESENTERLIST_H

#include "mxlist.h"

class MxPresenter;

// VTABLE: LEGO1 0x100d62f0 SYNTHETIC
// class MxPtrList<MxPresenter>

// VTABLE: LEGO1 0x100d6308
// SIZE 0x18
class MxPresenterList : public MxPtrList<MxPresenter> {
public:
	virtual MxS8 Compare(MxPresenter*, MxPresenter*) override; // vtable+0x14
};

typedef MxListCursorChildChild<MxPresenter*> MxPresenterListCursor;

// VTABLE: LEGO1 0x100d6350 SYNTHETIC
// class MxCollection<MxPresenter *>

// VTABLE: LEGO1 0x100d6368 SYNTHETIC
// class MxList<MxPresenter *>

#endif // MXPRESENTERLIST_H
