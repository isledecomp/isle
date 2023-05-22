#ifndef MXCORE_H
#define MXCORE_H

#include "mxbool.h"

class MxParam;

class MxCore
{
public:
  __declspec(dllexport) MxCore();
  __declspec(dllexport) virtual ~MxCore();
  __declspec(dllexport) virtual long Notify(MxParam &p);
  virtual long Tickle();
  virtual const char *GetClassName() const;
  virtual MxBool IsClass(const char *name) const;

private:
  unsigned int m_id;

};

#endif // MXCORE_H
