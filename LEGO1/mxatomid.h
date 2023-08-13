#ifndef MXATOMID_H
#define MXATOMID_H

#include "mxtypes.h"
#include "mxatomidcounter.h"

enum LookupMode
{
  LookupMode_Exact = 0,
  LookupMode_LowerCase = 1,
  LookupMode_UpperCase = 2,
  LookupMode_LowerCase2 = 3
};

class MxAtomId
{
public:
  __declspec(dllexport) MxAtomId(const char *, LookupMode);
  __declspec(dllexport) MxAtomId &operator=(const MxAtomId &id);
  __declspec(dllexport) ~MxAtomId();

  MxAtomId()
  {
    this->m_internal = 0;
  }

  inline MxBool operator ==(const MxAtomId &other) const
  {
    return this->m_internal == other.m_internal;
  }
  void Clear();

private:
  MxAtomIdCounter* GetCounter(const char *, LookupMode);
  void Destroy();

  const char *m_internal;
};

#endif // MXATOMID_H
