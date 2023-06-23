#ifndef LEGOWORLDPRESENTER_H
#define LEGOWORLDPRESENTER_H

#include "legoentitypresenter.h"

#ifndef undefined4
#define undefined4 int
#endif

class LegoWorldPresenter : public LegoEntityPresenter
{
public:
  LegoWorldPresenter();
  virtual ~LegoWorldPresenter(); // vtable+0x0

  __declspec(dllexport) static void configureLegoWorldPresenter(int param_1);

  virtual void VTable0x1c(); // vtable0x1c
  virtual void VTable0x60(undefined4 param); // vtable+0x60

  // VTABLE 0x100d8ee0
};

#endif // LEGOWORLDPRESENTER_H
