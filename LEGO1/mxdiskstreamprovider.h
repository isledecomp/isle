#ifndef MXDISKSTREAMPROVIDER_H
#define MXDISKSTREAMPROVIDER_H

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
  MxDiskStreamProviderThread m_thread;
  MxSemaphore m_busySemaphore;
  byte m_remainingWork;
  byte m_unk1;
  MxCriticalSection m_criticalSection;
  byte unk2[4];
  void* unk3;
  void *unk4;
};

#endif // MXDISKSTREAMPROVIDER_H
