#ifndef MXDISKSTREAMPROVIDER_H
#define MXDISKSTREAMPROVIDER_H

#include "decomp.h"
#include "mxstreamprovider.h"
#include "mxthread.h"
#include "mxcriticalsection.h"
#include "mxunklist.h"

class MxDiskStreamProvider;

// VTABLE 0x100dd130
class MxDiskStreamProviderThread : public MxThread
{
public:
  // Only inlined, no offset
  inline MxDiskStreamProviderThread()
    : MxThread()
    , m_target(NULL) {}

  MxResult Run() override;

private:
  MxDiskStreamProvider *m_target;
};

// VTABLE 0x100dd138
class MxDiskStreamProvider : public MxStreamProvider
{
public:
  MxDiskStreamProvider();

  virtual ~MxDiskStreamProvider() override;

  // OFFSET: LEGO1 0x100d1160
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x1010287c
    return "MxDiskStreamProvider";
  }

  // OFFSET: LEGO1 0x100d1170
  inline virtual MxBool IsA(const char *name) const override // vtable+0x10
  {
    return !strcmp(name, MxDiskStreamProvider::ClassName()) || MxStreamProvider::IsA(name);
  }

  MxResult WaitForWorkToComplete();

  void PerformWork();

  virtual MxResult SetResourceToGet(void* p_resource) override; //vtable+0x14
  virtual MxU32 GetFileSize() override; //vtable+0x18
  virtual MxU32 GetStreamBuffersNum() override; //vtable+0x1c
  virtual void vtable0x20(undefined4 p_unknown1) override; //vtable+0x20
  virtual MxU32 GetLengthInDWords() override; //vtable+0x24
  virtual void* GetBufferForDWords()override; //vtable+0x28

private:
  MxDiskStreamProviderThread m_thread; // 0x10
  MxSemaphore m_busySemaphore; // 0x2c
  undefined m_remainingWork; // 0x34
  undefined m_unk35; // 0x35
  MxCriticalSection m_criticalSection; // 0x38
  MxUnkList m_list;
};

#endif // MXDISKSTREAMPROVIDER_H
