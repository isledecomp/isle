#ifndef LEGOANIMACTOR_H
#define LEGOANIMACTOR_H

#include "legopathactor.h"

class LegoAnimActor : public LegoPathActor
{
public:
  virtual const char* ClassName() const;
  virtual MxBool IsA(const char *name) const;

  // VTABLE 0x100d5440
};

#endif // LEGOANIMACTOR_H
