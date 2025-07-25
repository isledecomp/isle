#include "legopalettepresenter.h"

#include "legovideomanager.h"
#include "misc.h"
#include "misc/legostorage.h"
#include "mxdsaction.h"
#include "mxdssubscriber.h"
#include "mxpalette.h"
#include "mxstreamchunk.h"

DECOMP_SIZE_ASSERT(LegoPalettePresenter, 0x68)

// FUNCTION: LEGO1 0x10079e50
LegoPalettePresenter::LegoPalettePresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x1007a070
LegoPalettePresenter::~LegoPalettePresenter()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x1007a0d0
void LegoPalettePresenter::Init()
{
	m_palette = NULL;
}

// FUNCTION: LEGO1 0x1007a0e0
void LegoPalettePresenter::Destroy(MxBool p_fromDestructor)
{
	ENTER(m_criticalSection);
	if (m_palette) {
		delete m_palette;
	}
	Init();
	m_criticalSection.Leave();
	if (!p_fromDestructor) {
		MxVideoPresenter::Destroy(FALSE);
	}
}

// FUNCTION: LEGO1 0x1007a120
void LegoPalettePresenter::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x1007a130
MxResult LegoPalettePresenter::ParsePalette(MxStreamChunk* p_chunk)
{
	MxU8 buffer[40];
	RGBQUAD palette[256];
	MxResult result = FAILURE;

	LegoMemory stream((char*) p_chunk->GetData());
	if (stream.Read(buffer, 40 * sizeof(MxU8)) == SUCCESS) {
		if (stream.Read(palette, 256 * 4 * sizeof(MxU8)) == SUCCESS) {
			m_palette = new MxPalette(palette);
			if (m_palette) {
				result = SUCCESS;
			}
		}
	}

	if (result != SUCCESS && m_palette) {
		delete m_palette;
		m_palette = NULL;
	}

	return result;
}

// FUNCTION: LEGO1 0x1007a230
void LegoPalettePresenter::ReadyTickle()
{
	MxStreamChunk* chunk = m_subscriber->PeekData();
	if (chunk) {
		if (chunk->GetTime() <= m_action->GetElapsedTime()) {
			ParseExtra();
			ProgressTickleState(e_starting);

			chunk = m_subscriber->PopData();
			MxResult result = ParsePalette(chunk);
			m_subscriber->FreeDataChunk(chunk);

			if (result == SUCCESS) {
				VideoManager()->RealizePalette(m_palette);
			}
			EndAction();
		}
	}
}
