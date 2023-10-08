#ifndef MXSTREAMPROVIDER_H
#define MXSTREAMPROVIDER_H

#include "decomp.h"
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

  virtual MxResult SetResourceToGet(void* p_resource); //vtable+0x14
  virtual MxU32 GetFileSize() = 0; //vtable+0x18
  virtual MxU32 vtable0x1C() = 0; //vtable+0x1c
  virtual void vtable0x20(undefined4 p_unknown1); //vtable+0x20
  virtual MxU32 GetLengthInDWords() = 0; //vtable+0x24
  virtual void* GetBufferForDWords() = 0; //vtable+0x28

protected:
  void *m_pLookup;
  MxDSFile* m_pFile;
};

#endif // MXSTREAMPROVIDER_H
