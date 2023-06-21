#ifndef LEGOCARBUILD_H
#define LEGOCARBUILD_H

#include "legoworld.h"

class LegoCarBuild : public LegoWorld
{
public:
  LegoCarBuild();

  virtual void FUN_10025e70(int param_1);
  virtual void FUN_100256c0(char param_1);
  virtual void __fastcall FUN_10022fc0(int* param_1);
  virtual void FUN_10023500(float* param_1, float* param_2);
  virtual void FUN_10023570(float* param_1, float* param_2);
  virtual void FUN_10023620(float* param_1, float* param_2);
};

#endif // LEGOCARBUILD_H
