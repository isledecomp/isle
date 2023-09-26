#ifndef MXSOUNDMANAGER_H
#define MXSOUNDMANAGER_H

#include "mxaudiomanager.h"

// VTABLE 0x100dc128
// SIZE 0x3c
// Base vtables are: MxCore -> 0x100dc6b0 -> MxAudioManager -> MxSoundManager
class MxSoundManager : public MxAudioManager
{
public:
  MxSoundManager();
  virtual ~MxSoundManager() override; // vtable+0x0

private:
  void Init();
  int m_unk30;
  int m_unk34;
};

#endif // MXSOUNDMANAGER_H
