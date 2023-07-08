#ifndef MXVARIABLE_H
#define MXVARIABLE_H

#include "mxstring.h"
#include "mxcore.h"

//VTABLE: 0x100d74a8
class MxVariable
{
public:
  MxVariable() {}
  MxVariable(const char *p_key)
  {
    m_key = p_key;
    m_key.ToUpperCase();    
  }
  MxVariable(const char *p_key, const char *p_value)
  {
    m_key = p_key;
    m_key.ToUpperCase();
    m_value = p_value;
  }
  virtual MxString *GetValue();
  virtual void SetValue(const char *);
  virtual void Destroy();

  inline const MxString *GetKey() const { return &m_key; }

protected:
  MxString m_key;
  MxString m_value;
};

#endif // MXVARIABLE_H
