#ifndef MXWAVEPRESENTER_H
#define MXWAVEPRESENTER_H

#include "mxsoundpresenter.h"

#include "decomp.h"

// VTABLE 0x100d49a8
// SIZE 0x6c
class MxWavePresenter : public MxSoundPresenter
{
private:
  void Init();

public:
  MxWavePresenter() {
    Init();
  }
  undefined4 m_unk54;
  undefined4 m_unk58;
  undefined4 m_unk5c;
  undefined4 m_unk60;
  undefined m_unk64;
  undefined m_unk65;
  undefined m_unk66;
  undefined m_unk67;
  undefined m_unk68;
};

#endif // MXWAVEPRESENTER_H
