#ifndef ISLE_H
#define ISLE_H

#include "legoworld.h"

#include "legoomni.h"

class Isle : public LegoWorld
{
public:
  Isle();
  
// OFFSET: LEGO1 0x10015790
static Isle* GetIsle()
{
  LegoOmni* legoOmni = LegoOmni::GetInstance();
  return legoOmni->isle;
}

  virtual void __fastcall FUN_10030fc0(int param_1);
  virtual int __fastcall  FUN_10033180(int param_1); // Return is undefined 4-byte value
  virtual void FUN_1003305(int* param_1);

  // SIZE 0x140
  // Radio at 0x12c
};

#endif // ISLE_H
