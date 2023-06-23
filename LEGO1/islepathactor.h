#ifndef ISLEPATHACTOR_H
#define ISLEPATHACTOR_H

#include "legopathactor.h"

#ifndef undefined
#define undefined int
#endif

class IslePathActor : public LegoPathActor
{
public:
  IslePathActor();

  virtual void Destroy(); // vtable+0x1c
  virtual void VTable0xec(undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, void*, char); // vtable+0xec
  
  // VTABLE 0x100d4398
  // SIZE >= 0x230
};

#endif // ISLEPATHACTOR_H
