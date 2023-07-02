#ifndef MXSTRINGVARIABLE_H
#define MXSTRINGVARIABLE_H
#include "mxstring.h"
#include "mxcore.h"
//VTABLE: 0x100d74a8
class MxStringVariable
{
public:
  __declspec(dllexport) MxStringVariable(const char *, const char *);
  MxStringVariable() {}
  virtual MxString *GetString();
  virtual void SetString(const char *colorString);
  virtual void Destroy();

protected:
  MxString m_name;
  MxString m_string;
};

#endif // MXSTRINGVARIABLE_H
