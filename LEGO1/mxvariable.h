#ifndef MXVARIABLE_H
#define MXVARIABLE_H

#include "mxstring.h"
#include "mxcore.h"

//VTABLE: 0x100d74a8
class MxVariable
{
public:
  __declspec(dllexport) MxVariable(const char *, const char *);
  MxVariable() {}
  virtual MxString *GetValue();
  virtual void SetValue(const char *);
  virtual void Destroy();

  inline const MxString *GetKey() const { return &m_value; }

protected:
  MxString m_key;
  MxString m_value;
};

#endif // MXVARIABLE_H
