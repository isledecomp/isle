#ifndef LEGOPLANTMANAGER_H
#define LEGOPLANTMANAGER_H

#include "mxcore.h"

class LegoPlantManager : public MxCore
{
public:
  LegoPlantManager();
  virtual ~LegoPlantManager(); // vtable+0x0

  virtual const char* GetClassName() const; // vtable+0xc

  void UnknownFunction1(int param_1, int param_2);

private:
  void Init();
  
  // VTABLE 0x100d6758
  // SIZE 0x2c
};

#endif // LEGOPLANTMANAGER_H
