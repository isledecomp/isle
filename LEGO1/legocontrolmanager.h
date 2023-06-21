#ifndef LEGOCONTROLMANAGER_H
#define LEGOCONTROLMANAGER_H

#include "mxcore.h"

class LegoControlManager : public MxCore
{
public:
  virtual ~LegoControlManager();

  virtual const char* GetClassName() const;
  virtual MxBool IsClass(const char *name) const;
};

#endif // LEGOCONTROLMANAGER_H
