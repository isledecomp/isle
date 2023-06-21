#ifndef GASSTATION_H
#define GASSTATION_H

#include "legoworld.h"

class GasStation : public LegoWorld
{
public:
  GasStation();
  
  int FUN_10005e70(int param_1); // Return is undefined 4-byte value

  // SIZE 0x128
  // Radio variable at 0x46, in constructor
};

#endif // GASSTATION_H
