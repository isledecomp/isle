#ifndef MXAUDIOMANAGER_H
#define MXAUDIOMANAGER_H

#include "decomp.h"
#include "mxmediamanager.h"

// VTABLE 0x100dc6e0
class MxAudioManager : public MxMediaManager
{
public:
  MxAudioManager();
  virtual ~MxAudioManager() override;

  virtual MxResult InitPresenters(); // vtable+14
  virtual void Destroy(); // vtable+18

private:
  void LockedReinitialize(MxBool);

  static MxS32 g_unkCount;

protected:
  void Init();

  undefined4 m_unk2c;
};

#endif // MXAUDIOMANAGER_H
