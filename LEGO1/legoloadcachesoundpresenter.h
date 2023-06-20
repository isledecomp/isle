#ifndef LEGOLOADCACHESOUNDPRESENTER_H
#define LEGOLOADCACHESOUNDPRESENTER_H

#include "mxwavepresenter.h"

class LegoLoadCacheSoundPresenter : public MxWavePresenter
{
public:
  LegoLoadCacheSoundPresenter();

private:
  void Init();

  // SIZE 0x90
};

#endif // LEGOLOADCACHESOUNDPRESENTER_H