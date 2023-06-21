#ifndef LEGOCACHESOUND_H
#define LEGOCACHESOUND_H

#include "mxcore.h"

class LegoCacheSound : public MxCore
{
public:
  // OFFSET: LEGO1 0x100064d0
  LegoCacheSound();

  // OFFSET: LEGO1 0x10006630
  ~LegoCacheSound();

  void FUN_10006920(int param_1);

private:
  // OFFSET: LEGO1 0x100066d0
  void Init();

  // VTABLE 0x100d4718
  // SIZE 0x88
};

#endif // LEGOCACHESOUND_H
