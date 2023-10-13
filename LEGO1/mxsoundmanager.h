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

  virtual MxResult StartDirectSound(undefined4 p_unknown1, MxBool p_unknown2); //vtable+0x30
  virtual void vtable0x34(); // vtable+0x34
  virtual void vtable0x38(); // vtable+0x38

private:
  void Init();
  void Destroy(MxBool p_fromDestructor);

  undefined4 m_unk30;
  LPDIRECTSOUNDBUFFER m_dsBuffer; // 0x34
  undefined m_unk35[4];
};

#endif // MXSOUNDMANAGER_H
