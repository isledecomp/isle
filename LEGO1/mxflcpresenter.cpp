#include "mxflcpresenter.h"

#include "decomp.h"
#include "mxbitmap.h"
#include "mxomni.h"
#include "mxpalette.h"
#include "mxvideomanager.h"

DECOMP_SIZE_ASSERT(MxFlcPresenter, 0x68);

// OFFSET: LEGO1 0x100b3310
MxFlcPresenter::MxFlcPresenter()
{
	this->m_unk64 = 0;
	this->m_flags &= 0xfd;
	this->m_flags &= 0xfb;
}

// OFFSET: LEGO1 0x100b3420
MxFlcPresenter::~MxFlcPresenter()
{
	if (this->m_unk64) {
		delete this->m_unk64;
	}
}

// OFFSET: LEGO1 0x100b3620
void MxFlcPresenter::vtable70()
{
	MxPalette* pal = m_bitmap->CreatePalette();
	MVideoManager()->RealizePalette(pal);
	if (pal) {
		delete pal;
	}
}
