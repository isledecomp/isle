#include "mxsmkpresenter.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxSmkPresenter, 0x720);

// OFFSET: LEGO1 0x100b3650 STUB
MxSmkPresenter::MxSmkPresenter()
{
  // TODO
}

// OFFSET: LEGO1 0x100b38d0 STUB
void MxSmkPresenter::Init()
{
  // TODO
}

// OFFSET: LEGO1 0x100b3960
void MxSmkPresenter::VTable0x60()
{
  if (m_bitmap) {
    delete m_bitmap;
  }

  m_bitmap = new MxBitmap();
  m_bitmap->SetSize(m_smkWidth, m_smkHeight, NULL, NULL);
}
