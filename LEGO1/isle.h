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

  // SIZE 0x140
  // Radio at 0x12c
};

#endif // ISLE_H
