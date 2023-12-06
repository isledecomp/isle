#ifndef MXPRESENTERLIST_H
#define MXPRESENTERLIST_H

#include "mxlist.h"

class MxPresenter;

// VTABLE: LEGO1 0x100d62f0
// class MxPtrList<MxPresenter>

// VTABLE: LEGO1 0x100d6308
// SIZE 0x18
class MxPresenterList : public MxPtrList<MxPresenter> {
public:
	virtual MxS8 Compare(MxPresenter*, MxPresenter*) override; // vtable+0x14
};

class MxPresenterListCursor : public MxPtrListCursor<MxPresenter> {
public:
	MxPresenterListCursor(MxPresenterList* p_list) : MxPtrListCursor<MxPresenter>(p_list){};
};

// VTABLE: LEGO1 0x100d6350
// class MxCollection<MxPresenter *>

// VTABLE: LEGO1 0x100d6368
// class MxList<MxPresenter *>

#endif // MXPRESENTERLIST_H
