#ifndef MXDISKSTREAMPROVIDER_H
#define MXDISKSTREAMPROVIDER_H

#include "decomp.h"
#include "mxstreamprovider.h"
#include "mxthread.h"
#include "mxcriticalsection.h"

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

private:
  MxDiskStreamProviderThread m_thread; // 0x10
  MxSemaphore m_busySemaphore; // 0x2c
  byte m_remainingWork; // 0x34
  byte m_unk1; // 0x35
  byte m_unk36[2];
  MxCriticalSection m_criticalSection; // 0x38
  undefined m_unk54; // 0x54
  byte m_unk55[3];
  void* m_unk4;
  void *m_unk5;
};

#endif // MXDISKSTREAMPROVIDER_H
