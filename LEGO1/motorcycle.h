#ifndef MOTORCYCLE_H
#define MOTORCYCLE_H

#include "islepathactor.h"

class Motorcycle : public IslePathActor
{
public:
  Motorcycle();

  virtual void __fastcall FUN_10035c50(int* param_1);
  virtual void __fastcall FUN_10035bc0(int* param_1);

  // VTABLE 0x100d7090
  // SIZE 0x16c
};

#endif // MOTORCYCLE_H
