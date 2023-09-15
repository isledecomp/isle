#ifndef MXAUDIOMANAGER_H
#define MXAUDIOMANAGER_H

#include "mxmediamanager.h"

// VTABLE 0x100dc6e0
class MxAudioManager : public MxMediaManager
{
public:
  MxAudioManager();
  virtual ~MxAudioManager() override;

  void LockedReinitialize(MxS8);
protected:
  void Init();

  int m_unk2c;
};

#endif // MXAUDIOMANAGER_H
