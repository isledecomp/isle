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

// TODO
struct MxDiskStreamListNode {
  MxDiskStreamListNode *m_unk00;
  MxDiskStreamListNode *m_unk04;
  undefined4 m_unk08;
};

// TODO
struct MxDiskStreamList {
  inline MxDiskStreamList() {
    undefined unk;
    this->m_unk00 = unk;

    MxDiskStreamListNode *node = new MxDiskStreamListNode();
    node->m_unk00 = node;
    node->m_unk04 = node;
    
    this->m_head = node;
    this->m_count = 0;
  }

  undefined m_unk00;
  MxDiskStreamListNode *m_head;
  MxU32 m_count;
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
  undefined m_remainingWork; // 0x34
  undefined m_unk35; // 0x35
  MxCriticalSection m_criticalSection; // 0x38
  MxDiskStreamList m_list;
};

#endif // MXDISKSTREAMPROVIDER_H
