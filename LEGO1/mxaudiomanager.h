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

  void Reinitialize();

private:
  void LockedReinitialize(MxBool);

protected:
  void Init();

  undefined4 m_unk2c;
};

#endif // MXAUDIOMANAGER_H
