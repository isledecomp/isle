#ifndef MXCOMPOSITEPRESENTER_H
#define MXCOMPOSITEPRESENTER_H

#include "mxpresenter.h"

class MxCompositePresenter : public MxPresenter
{
public:
  MxCompositePresenter();
  virtual ~MxCompositePresenter(); // vtable+0x0

  virtual long Notify(MxParam &p); // vtable+0x4, MxCore override

  // VTABLE 0x100dc618
};

#endif // MXCOMPOSITEPRESENTER_H
