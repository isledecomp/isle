#ifndef MXATOMID_H
#define MXATOMID_H

#include "mxbinarytree.h"
#include "mxstring.h"
#include "mxtypes.h"

enum LookupMode
{
  LookupMode_Exact = 0,
  LookupMode_LowerCase = 1,
  LookupMode_UpperCase = 2,
  LookupMode_LowerCase2 = 3
};

// SIZE 0x4
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

  // TODO: belongs here?
  TreeValue *try_to_open(const char *, LookupMode);
  void Destroy();
  void Clear();
  
private:
  const char *m_internal;
};

#endif // MXATOMID_H
