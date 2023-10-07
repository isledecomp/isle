#ifndef MXSOUNDMANAGER_H
#define MXSOUNDMANAGER_H

#include "decomp.h"
#include "mxaudiomanager.h"

#include <dsound.h>

// VTABLE 0x100dc128
// SIZE 0x3c
class MxSoundManager : public MxAudioManager
{
public:
  MxSoundManager();
  virtual ~MxSoundManager() override; // vtable+0x0

private:
  void Init();
  void Destroy(MxBool);

  undefined4 m_unk30;
  LPDIRECTSOUNDBUFFER m_dsBuffer; // 0x34
  undefined m_unk35[4];
};

#endif // MXSOUNDMANAGER_H
