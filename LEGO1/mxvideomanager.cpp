#include "mxvideomanager.h"
#include "mxautolocker.h"
#include "mxpresenter.h"
#include "mxticklemanager.h"
#include "legoomni.h"

// OFFSET: LEGO1 0x100be1f0
MxVideoManager::MxVideoManager()
{
  Init();
}

// OFFSET: LEGO1 0x100be2a0
MxVideoManager::~MxVideoManager()
{
  Destroy(TRUE);
}

// OFFSET: LEGO1 0x100bea90
MxResult MxVideoManager::Tickle()
{
  MxAutoLocker lock(&this->m_criticalSection);

  SortPresenterList();

  MxPresenter *presenter;
  MxPresenterListCursor cursor(this->m_presenters);

  while (cursor.Next(presenter))
    presenter->Tickle();

  cursor.Reset();

  while (cursor.Next(presenter))
    presenter->PutData();

  UpdateRegion();
  m_region->Reset();

  return SUCCESS;
}

// OFFSET: LEGO1 0x100be320
MxResult MxVideoManager::Init()
{
  this->m_pDirectDraw = NULL;
  this->m_pDDSurface = NULL;
  this->m_displaySurface = NULL;
  this->m_region = NULL;
  this->m_videoParam.SetPalette(NULL);
  this->m_unk60 = FALSE;
  return SUCCESS;
}

// OFFSET: LEGO1 0x100be340
void MxVideoManager::Destroy(MxBool p_fromDestructor)
{
  if (m_thread != NULL) {
    m_thread->Terminate();
    delete m_thread;
  }
  else
    TickleManager()->UnregisterClient(this);

  m_criticalSection.Enter();

  if (m_displaySurface)
    delete m_displaySurface;

  if (m_region)
    delete m_region;

  if (m_videoParam.GetPalette())
    delete m_videoParam.GetPalette();

  if (m_unk60) {
    if (m_pDirectDraw)
      m_pDirectDraw->Release();
    if (m_pDDSurface)
      m_pDDSurface->Release();
  }

  Init();
  m_criticalSection.Leave();

  if (!p_fromDestructor)
    MxMediaManager::Destroy();
}

// OFFSET: LEGO1 0x100be440
void MxVideoManager::SortPresenterList()
{
  if (this->m_presenters->GetCount() <= 1)
    return;

  MxPresenterListCursor a(this->m_presenters);
  MxPresenterListCursor b(this->m_presenters);
  MxU32 count = this->m_presenters->GetCount() - 1;
  MxBool finished;

  if (count != 0) {
    do {
      a.Reset();
      b.Head();

      finished = TRUE;
      for (MxU32 i = count; i != 0; i--) {
        MxPresenter *p_a, *p_b;

        a.Next(p_a);
        b.Next(p_b);

        if (p_a->GetDisplayZ() < p_b->GetDisplayZ()) {
          a.SetValue(p_b);
          b.SetValue(p_a);
          finished = FALSE;
        }
      }
    } while (!finished && --count != 0);
  }
}

// OFFSET: LEGO1 0x100be3e0 STUB
void MxVideoManager::UpdateRegion()
{
  // TODO
}

// OFFSET: LEGO1 0x100bea50
void MxVideoManager::Destroy()
{
  Destroy(FALSE);
}

// OFFSET: LEGO1 0x100bea60 STUB
void MxVideoManager::InvalidateRect(MxRect32 &p_rect)
{
  // TODO
}

// OFFSET: LEGO1 0x100bebe0
MxLong MxVideoManager::RealizePalette(MxPalette *p_palette)
{
  PALETTEENTRY paletteEntries[256];

  this->m_criticalSection.Enter();

  if (p_palette && this->m_videoParam.GetPalette()) {
    p_palette->GetEntries(paletteEntries);
    this->m_videoParam.GetPalette()->SetEntries(paletteEntries);
    this->m_displaySurface->SetPalette(this->m_videoParam.GetPalette());
  }

  this->m_criticalSection.Leave();
  return 0;
}

// OFFSET: LEGO1 0x100be600 STUB
void MxVideoManager::vtable0x28()
{

}

// OFFSET: LEGO1 0x100bebe0 STUB
MxResult MxVideoManager::vtable0x2c(MxVideoParam& p_videoParam, undefined4 p_unknown1, MxU8 p_unknown2)
{
  return FAILURE;
}
