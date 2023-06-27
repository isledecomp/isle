#ifndef LEGOANIMACTOR_H
#define LEGOANIMACTOR_H

#include "legopathactor.h"

class LegoAnimActor : public LegoPathActor
{
public:
  virtual const char* GetClassName() const;
  virtual MxBool IsClass(const char *name) const;

  // VTABLE 0x100d5440
};

#endif // LEGOANIMACTOR_H
