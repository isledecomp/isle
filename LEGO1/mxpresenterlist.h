#ifndef MXPRESENTERLIST_H
#define MXPRESENTERLIST_H

#include "mxlist.h"

class MxPresenter;

// Unclear what the purpose of this class is
// VTABLE 0x100d62f0
// SIZE 0x18
class MxPresenterListParent : public MxList<MxPresenter>
{
public:
  MxPresenterListParent() {
    m_customDestructor = Destroy;
  }
};

// VTABLE 0x100d6308
// SIZE 0x18
class MxPresenterList : public MxPresenterListParent
{
public:
  virtual MxS8 Compare(MxPresenter *, MxPresenter *); // +0x14
};

#endif // MXPRESENTERLIST_H
