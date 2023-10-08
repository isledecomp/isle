#include "mxvideopresenter.h"
#include "MxVideoManager.h"

DECOMP_SIZE_ASSERT(MxVideoPresenter, 0x64);

// OFFSET: LEGO1 0x1000c700
void MxVideoPresenter::VTable0x5c(undefined4 p_unknown1)
{
  // Empty
}

// OFFSET: LEGO1 0x1000c710
void MxVideoPresenter::VTable0x60()
{
  // Empty
}

// OFFSET: LEGO1 0x1000c720
void MxVideoPresenter::VTable0x68(undefined4 p_unknown1)
{
  // Empty
}

// OFFSET: LEGO1 0x1000c730
void MxVideoPresenter::VTable0x70()
{
  // Empty
}

// OFFSET: LEGO1 0x1000c740
MxVideoPresenter::~MxVideoPresenter()
{
  Destroy(TRUE);
}

// OFFSET: LEGO1 0x1000c7a0
void MxVideoPresenter::InitVirtual()
{
  Destroy(FALSE);
}

// OFFSET: LEGO1 0x1000c7b0
MxCore* MxVideoPresenter::VTable0x78()
{
  return m_unk58;
}

// OFFSET: LEGO1 0x1000c7c0
MxBool MxVideoPresenter::VTable0x7c()
{
  return (m_bitmap != NULL) || (m_unk54 != NULL);
}

// OFFSET: LEGO1 0x1000c7e0
MxS32 MxVideoPresenter::GetWidth()
{
  return m_unk54 ? m_unk54->width
                 : m_bitmap->GetBmiHeader()->biWidth;
}

// OFFSET: LEGO1 0x1000c800
MxS32 MxVideoPresenter::GetHeight()
{
  return m_unk54 ? m_unk54->height
                 : m_bitmap->GetBmiHeader()->biHeight;
}

// OFFSET: LEGO1 0x100b2760
void MxVideoPresenter::Init()
{
  m_bitmap = NULL;
  m_unk54 = NULL;
  m_unk5c = 1;
  m_unk58 = NULL;
  m_unk60 = -1;
  m_flags = m_flags & 0xfe;
  if (MVideoManager() != NULL)
  {
    MVideoManager();
    m_flags = m_flags | 2;
    m_flags = m_flags & 0xfb;
  }
  m_flags = m_flags & 0xf7;
  m_flags = m_flags & 0xef;
}

// OFFSET: LEGO1 0x100b27b0
void MxVideoPresenter::Destroy(MxBool p_reinit)
{
  MxRect32 rect;
  if (MVideoManager() != NULL)
  {
    MVideoManager()->RemovePresenter(*this);
  }

  if(m_unk58 != NULL)
  {
    m_unk58->Tickle();
    m_unk58 = NULL;
    m_flags = m_flags & 0xfd;
    m_flags = m_flags & 0xfb;
  }

  if (MVideoManager() != NULL && m_unk54 != NULL && m_bitmap != NULL)
  {
    rect.m_right = GetWidth() + rect.m_left;
    rect.m_bottom = GetHeight() + rect.m_top;
    rect.m_left = GetLocationX();
    rect.m_top = GetLocationY();

    MVideoManager()->InvalidateRect(rect);
    MVideoManager()->vtable0x34(rect.m_left, rect.m_top, rect.GetWidth(), rect.GetHeight());
  }

  delete m_bitmap;
  delete m_unk58;

  Init();
  if (!p_reinit)
  {
      // TODO MxMediaPresenter->Destroy(FALSE)
  }
}

// OFFSET: LEGO1 0x100b28b0 STUB
void MxVideoPresenter::VTable0x64()
{
  // TODO
}

// OFFSET: LEGO1 0x100b2a70 STUB
void MxVideoPresenter::VTable0x6c()
{
  // TODO
}

// OFFSET: LEGO1 0x100b3300
undefined MxVideoPresenter::VTable0x74()
{
  return 0;
}
