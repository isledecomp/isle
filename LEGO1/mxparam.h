#ifndef MXPARAM_H
#define MXPARAM_H

#include "mxomnicreateparambase.h"

class MxCore;

// VTABLE 0x100d56e0
class MxParam : public MxOmniCreateParamBase
{
public:
  inline MxParam(int p_type, MxCore *p_sender) : MxOmniCreateParamBase(), m_type(p_type), m_sender(p_sender){}

  virtual ~MxParam(){}; // vtable+0x0 (scalar deleting destructor)
  virtual MxParam *Clone(); // vtable+0x4

  inline int GetType() const
  {
    return m_type;
  }

  inline MxCore *GetSender() const
  {
    return m_sender;
  }

private:
  int m_type; // 0x4
  MxCore *m_sender; // 0x8
};

#endif // MXPARAM_H
