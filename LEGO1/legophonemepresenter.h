#ifndef LEGOPHONEMEPRESENTER_H
#define LEGOPHONEMEPRESENTER_H

#include "mxflcpresenter.h"

class LegoPhonemePresenter : public MxFlcPresenter
{
public:
  virtual ~LegoPhonemePresenter();

  virtual const char* GetClassName() const;

  virtual void FUN_1004e840(int param_1);
};

#endif // LEGOPHONEMEPRESENTER_H
