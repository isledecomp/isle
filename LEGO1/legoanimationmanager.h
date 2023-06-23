#ifndef LEGOANIMATIONMANAGER_H
#define LEGOANIMATIONMANAGER_H

#include "mxcore.h"

class LegoAnimationManager : public MxCore
{
public:
  LegoAnimationManager();
  virtual ~LegoAnimationManager(); // vtable+0x0

  virtual long Notify(MxParam &p); // vtable+0x4
  virtual long Tickle(); // vtable+0x8
  __declspec(dllexport) static void configureLegoAnimationManager(int param_1);
  
private:
  void Init();
  
  // VTABLE 0x100d8c18
  // SIZE 0x500
};

#endif // LEGOANIMATIONMANAGER_H
