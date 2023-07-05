#ifndef MXVARIABLETABLE_H
#define MXVARIABLETABLE_H

#include "mxcore.h"
#include "mxvariable.h"

// VTABLE 0x100dc1c8
// SIZE 0x28
class MxVariableTable : public MxCore
{
public:
  __declspec(dllexport) const char * GetVariable(const char *key);
  __declspec(dllexport) void SetVariable(MxVariable *var);
  __declspec(dllexport) void SetVariable(const char *key, const char *value);

  virtual int KeyChecksum(MxVariable *); // +0x18

//private:
  int m_unk8;
  void (*m_unkc)(void *); // +0xc
  void *m_table; // +0x10
  int m_tableLen; // +0x14
  int m_unk18;
  int m_unk1c;
  int m_unk20;
  int m_unk24;
};

#endif // MXVARIABLETABLE_H
