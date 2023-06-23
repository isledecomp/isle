#ifndef MXVIDEOPRESENTER_H
#define MXVIDEOPRESENTER_H

#include "mxmediapresenter.h"

class MxVideoPresenter : public MxMediaPresenter
{
public:
  virtual void EndAction(); // vtable+0x40, override MxPresenter
};

#endif // MXVIDEOPRESENTER_H
