#ifndef MXVARIABLETABLE_H
#define MXVARIABLETABLE_H

#include "mxtypes.h"
#include "mxhashtable.h"
#include "mxvariable.h"


// VTABLE 0x100dc1c8
// SIZE 0x28
class MxVariableTable : protected MxHashTable<MxVariable>
{
public:
  __declspec(dllexport) void SetVariable(const char *key, const char *value);
  __declspec(dllexport) void SetVariable(MxVariable *var);
  __declspec(dllexport) const char * GetVariable(const char *key);

  virtual MxS8 Compare(MxVariable *, MxVariable *); // +0x14
  virtual MxU32 Hash(MxVariable *); // +0x18
};

#endif // MXVARIABLETABLE_H
