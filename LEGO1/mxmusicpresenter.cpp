#include "mxmusicpresenter.h"

#include "decomp.h"
#include "mxmusicmanager.h"
#include "mxomni.h"

DECOMP_SIZE_ASSERT(MxMusicPresenter, 0x54);

// OFFSET: LEGO1 0x100c22c0
MxMusicPresenter::MxMusicPresenter()
{
  Init();
}

// OFFSET: LEGO1 0x100c24e0
MxMusicPresenter::~MxMusicPresenter()
{
  Destroy(TRUE);
}

// OFFSET: LEGO1 0x100c2540
void MxMusicPresenter::Init()
{
}

// OFFSET: LEGO1 0x100c2550 STUB
void MxMusicPresenter::Destroy(MxBool)
{
  // TODO
}

// OFFSET: LEGO1 0x100c25a0
MxResult MxMusicPresenter::AddToMusicManager()
{
  MxResult ret = -1;
  if(MusicManager()) {
    ret = 0;
    MusicManager()->AddPresenter(*this);
  }
  return ret;
} 

// OFFSET: LEGO1 0x100c25d0
void MxMusicPresenter::vtable38()
{
  // TODO: Name this function when we know what the argument to Destroy does
  Destroy(FALSE);
}
