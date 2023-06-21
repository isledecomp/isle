#ifndef LEGOENTITY_H
#define LEGOENTITY_H

#include "mxentity.h"

class LegoEntity : public MxEntity
{
public:
  LegoEntity();
  __declspec(dllexport) virtual ~LegoEntity();

  virtual const char* GetClassName() const;
  virtual MxBool IsClass(const char *name) const;
};

#endif // LEGOENTITY_H
