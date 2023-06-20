#ifndef MXSMKPRESENTER_H
#define MXSMKPRESENTER_H

#include "mxvideopresenter.h"

class MxSmkPresenter : public MxVideoPresenter
{
public:
  MxSmkPresenter();
  
private:
  void __fastcall Init();
  
  // SIZE 0x720
};

#endif // MXSMKPRESENTER_H
