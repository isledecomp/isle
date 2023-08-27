#ifndef MXMEDIAMANGER_H
#define MXMEDIAMANGER_H

#include "mxcore.h"
#include "mxcriticalsection.h"
#include "mxthread.h"
#include "mxtypes.h"

// VTABLE 0x100dc6b0
class MxMediaManager : public MxCore
{
public:
  MxMediaManager();
  virtual ~MxMediaManager() override;

  MxResult Init();
  void Teardown();
private:
  void* m_unk08;
  MxThread* m_thread; // 0xc

protected:
  MxCriticalSection m_criticalSection; // 0x10
};

#endif // MXMEDIAMANGER_H
