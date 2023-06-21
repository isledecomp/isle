#ifndef ISLEACTOR_H
#define ISLEACTOR_H

#include "legoentity.h"

class IsleActor : public LegoEntity
{
  virtual const char* GetClassName() const;
  virtual MxBool IsClass(const char *name) const;
};

#endif // ISLEACTOR_H