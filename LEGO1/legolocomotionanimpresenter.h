#ifndef LEGOLOCOMOTIONANIMPRESENTER_H
#define LEGOLOCOMOTIONANIMPRESENTER_H

#include "legoloopinganimpresenter.h"

// VTABLE 0x100d9170
class LegoLocomotionAnimPresenter : public LegoLoopingAnimPresenter
{
public:
  LegoLocomotionAnimPresenter();

  // OFFSET: LEGO1 0x1006ce50
  inline const char *ClassName() const override // vtable+0xc
  {
    // 0x100f06e4
    return "LegoLocomotionAnimPresenter";
  }

  // OFFSET: LEGO1 0x1006ce60
  inline MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, LegoLocomotionAnimPresenter::ClassName()) || LegoLoopingAnimPresenter::IsA(name);
  }
  
private:
  void Init();

};

#endif // LEGOLOCOMOTIONANIMPRESENTER_H
