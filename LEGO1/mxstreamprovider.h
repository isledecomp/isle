#ifndef MXSTREAMPROVIDER_H
#define MXSTREAMPROVIDER_H

#include "mxcore.h"
#include "mxdsfile.h"

// VTABLE 0x100dd100
class MxStreamProvider : public MxCore
{
public:
  inline MxStreamProvider() {
    this->m_pLookup = NULL;
    this->m_pFile = NULL;
  }

  // OFFSET: LEGO1 0x100d07e0
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    return "MxStreamProvider";
  }

  // OFFSET: LEGO1 0x100d07f0
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxStreamProvider::ClassName()) || MxCore::IsA(name);
  }

protected:
  void *m_pLookup;
  MxDSFile* m_pFile;
};

#endif // MXSTREAMPROVIDER_H
