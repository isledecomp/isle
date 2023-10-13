#include "mxvideopresenter.h"

DECOMP_SIZE_ASSERT(MxVideoPresenter, 0x64);

// OFFSET: LEGO1 0x1000c700 STUB
void MxVideoPresenter::VTable0x5c()
{
  // TODO
}

// OFFSET: LEGO1 0x1000c710
void MxVideoPresenter::VTable0x60()
{
  // Empty
}

// OFFSET: LEGO1 0x1000c720 STUB
void MxVideoPresenter::VTable0x68()
{
  // TODO
}

// OFFSET: LEGO1 0x1000c730 STUB
void MxVideoPresenter::VTable0x70()
{
  // TODO
}

// OFFSET: LEGO1 0x1000c740
MxVideoPresenter::~MxVideoPresenter()
{
  Destroy(TRUE);
}

// OFFSET: LEGO1 0x1000c7a0 STUB
void MxVideoPresenter::Destroy()
{
  // TODO
}

// OFFSET: LEGO1 0x1000c7b0 STUB
void MxVideoPresenter::VTable0x78()
{
  // TODO
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

// OFFSET: LEGO1 0x100b2760 STUB
void MxVideoPresenter::Init()
{
  // TODO
}

// OFFSET: LEGO1 0x100b27b0 STUB
void MxVideoPresenter::Destroy(MxBool p_fromDestructor)
{
  // TODO
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

// OFFSET: LEGO1 0x100b3300 STUB
void MxVideoPresenter::VTable0x74()
{
  // TODO
}
