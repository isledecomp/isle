#ifndef MXENTITY_H
#define MXENTITY_H

#include "mxcore.h"

class MxEntity : public MxCore
{
public:
  virtual const char* GetClassName() const;
  virtual MxBool IsClass(const char *name) const;
};

#endif // MXENTITY_H