#include "mxvideomanager.h"
#include "mxautolocker.h"
#include "mxpresenter.h"

// OFFSET: LEGO1 0x100be1f0
MxVideoManager::MxVideoManager()
{
  Init();
}

// OFFSET: LEGO1 0x100be2a0 STUB
MxVideoManager::~MxVideoManager()
{
  // TODO
}

// OFFSET: LEGO1 0x100bea90
MxLong MxVideoManager::Tickle()
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
