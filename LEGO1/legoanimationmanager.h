#ifndef LEGOANIMATIONMANAGER_H
#define LEGOANIMATIONMANAGER_H

#include "mxcore.h"

class LegoAnimationManager : public MxCore
{
public:
  LegoAnimationManager();

  __declspec(dllexport) static void configureLegoAnimationManager(int param_1);
  
private:
  void Init();
  
  // VTABLE 0x100d8c18
  // SIZE 0x500
};

#endif // LEGOANIMATIONMANAGER_H
