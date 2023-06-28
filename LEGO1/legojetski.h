#ifndef LEGOJETSKI_H
#define LEGOJETSKI_H

#include "legojetskiraceactor.h"

class LegoJetski : public LegoJetskiRaceActor
{
public:
  virtual const char* ClassName() const;
  virtual MxBool IsA(const char *name) const;

  // VTABLE 0x100d5a40
};


#endif // LEGOJETSKI_H
