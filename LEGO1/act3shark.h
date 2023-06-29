#ifndef ACT3SHARK_H
#define ACT3SHARK_H

#include "legoanimactor.h"

// VTABLE 0x100d7920
class Act3Shark : public LegoAnimActor
{
public:
  // OFFSET: LEGO1 0x100430c0
  inline virtual const char *ClassName() const override
  {
    // 0x100f03a0
    return "Act3Shark";
  }
};

#endif // ACT3SHARK_H
