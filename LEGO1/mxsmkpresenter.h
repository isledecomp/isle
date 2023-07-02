#ifndef MXSMKPRESENTER_H
#define MXSMKPRESENTER_H

#include "mxvideopresenter.h"

#include "decomp.h"

// VTABLE 0x100dc348
// SIZE 0x720
class MxSmkPresenter : public MxVideoPresenter
{
public:
  MxSmkPresenter();

  undefined4 m_unk64[430];
  undefined4 m_unk71c;
private:
  void Init();
};

#endif // MXSMKPRESENTER_H
