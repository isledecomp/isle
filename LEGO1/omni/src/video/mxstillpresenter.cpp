#include "mxstillpresenter.h"

#include "decomp.h"
#include "define.h"
#include "mxcompositepresenter.h"
#include "mxdsmediaaction.h"
#include "mxmisc.h"
#include "mxomni.h"
#include "mxutilities.h"
#include "mxvideomanager.h"

DECOMP_SIZE_ASSERT(MxStillPresenter, 0x6c);

// GLOBAL: LEGO1 0x101020e0
// STRING: LEGO1 0x10101eb0
const char* g_strBmpIsmap = "BMP_ISMAP";

// FUNCTION: LEGO1 0x100b9c70
void MxStillPresenter::Destroy(MxBool p_fromDestructor)
{
	m_criticalSection.Enter();

	if (m_bitmapInfo) {
		delete m_bitmapInfo;
	}
	m_bitmapInfo = NULL;

	m_criticalSection.Leave();

	if (!p_fromDestructor) {
		MxVideoPresenter::Destroy(FALSE);
	}
}

// FUNCTION: LEGO1 0x100b9cc0
void MxStillPresenter::LoadHeader(MxStreamChunk* p_chunk)
{
	if (m_bitmapInfo) {
		delete m_bitmapInfo;
	}

	MxU8* data = new MxU8[p_chunk->GetLength()];
	m_bitmapInfo = (MxBITMAPINFO*) data;
	memcpy(m_bitmapInfo, p_chunk->GetData(), p_chunk->GetLength());
}

// FUNCTION: LEGO1 0x100b9d10
void MxStillPresenter::CreateBitmap()
{
	if (m_bitmap) {
		delete m_bitmap;
	}

	m_bitmap = new MxBitmap;
	m_bitmap->ImportBitmapInfo(m_bitmapInfo);

	delete m_bitmapInfo;
	m_bitmapInfo = NULL;
}

// FUNCTION: LEGO1 0x100b9db0
void MxStillPresenter::NextFrame()
{
	MxStreamChunk* chunk = NextChunk();
	LoadFrame(chunk);
	m_subscriber->FreeDataChunk(chunk);
}

// FUNCTION: LEGO1 0x100b9dd0
void MxStillPresenter::LoadFrame(MxStreamChunk* p_chunk)
{
	memcpy(m_bitmap->GetBitmapData(), p_chunk->GetData(), p_chunk->GetLength());

	// MxRect32 rect(m_location, MxSize32(GetWidth(), GetHeight()));
	MxS32 height = GetHeight() - 1;
	MxS32 width = GetWidth() - 1;
	MxS32 x = m_location.GetX();
	MxS32 y = m_location.GetY();

	MxRect32 rect(x, y, width + x, height + y);
	MVideoManager()->InvalidateRect(rect);

	if (GetBit1()) {
		undefined4 und = 0;
		m_unk0x58 = MxOmni::GetInstance()->GetVideoManager()->GetDisplaySurface()->VTable0x44(
			m_bitmap,
			&und,
			GetBit3(),
			m_action->GetFlags() & MxDSAction::c_bit4
		);

		delete m_alpha;
		m_alpha = new AlphaMask(*m_bitmap);

		delete m_bitmap;
		m_bitmap = NULL;

		if (m_unk0x58 && und) {
			SetBit2(TRUE);
		}
		else {
			SetBit2(FALSE);
		}
	}
}

// FUNCTION: LEGO1 0x100b9f30
void MxStillPresenter::RealizePalette()
{
	MxPalette* palette = m_bitmap->CreatePalette();
	MVideoManager()->RealizePalette(palette);
	delete palette;
}

// FUNCTION: LEGO1 0x100b9f60
void MxStillPresenter::StartingTickle()
{
	MxVideoPresenter::StartingTickle();

	if (m_currentTickleState == e_streaming && ((MxDSMediaAction*) m_action)->GetPaletteManagement()) {
		RealizePalette();
	}
}

// FUNCTION: LEGO1 0x100b9f90
void MxStillPresenter::StreamingTickle()
{
	MxStreamChunk* chunk = CurrentChunk();

	if (chunk && m_action->GetElapsedTime() >= chunk->GetTime()) {
		m_chunkTime = chunk->GetTime();
		NextFrame();
		ProgressTickleState(e_repeating);

		if (m_action->GetDuration() == -1 && m_compositePresenter) {
			m_compositePresenter->VTable0x60(this);
		}
	}
}

// FUNCTION: LEGO1 0x100b9ff0
void MxStillPresenter::RepeatingTickle()
{
	if (m_action->GetDuration() != -1) {
		if (m_action->GetElapsedTime() >= m_action->GetStartTime() + m_action->GetDuration()) {
			ProgressTickleState(e_unk5);
		}
	}
}

// FUNCTION: LEGO1 0x100ba040
void MxStillPresenter::SetPosition(MxS32 p_x, MxS32 p_y)
{
	MxS32 x = m_location.GetX();
	MxS32 y = m_location.GetY();
	m_location.SetX(p_x);
	m_location.SetY(p_y);

	if (IsEnabled()) {
		// Most likely needs to work with MxSize32 and MxPoint32
		MxS32 height = GetHeight() - 1;
		MxS32 width = GetWidth() - 1;

		MxRect32 rectA(x, y, width + x, height + y);
		MxRect32 rectB(m_location.GetX(), m_location.GetY(), width + m_location.GetX(), height + m_location.GetY());

		MVideoManager()->InvalidateRect(rectA);
		MVideoManager()->UpdateView(rectA.GetLeft(), rectA.GetTop(), rectA.GetWidth(), rectA.GetHeight());

		MVideoManager()->InvalidateRect(rectB);
		MVideoManager()->UpdateView(rectB.GetLeft(), rectB.GetTop(), rectB.GetWidth(), rectB.GetHeight());
	}
}

// FUNCTION: LEGO1 0x100ba140
void MxStillPresenter::Enable(MxBool p_enable)
{
	MxPresenter::Enable(p_enable);

	if (MVideoManager() && (m_alpha || m_bitmap)) {
		// MxRect32 rect(m_location, MxSize32(GetWidth(), GetHeight()));
		MxS32 height = GetHeight();
		MxS32 width = GetWidth();
		MxS32 x = m_location.GetX();
		MxS32 y = m_location.GetY();

		MxRect32 rect(x, y, width + x, height + y);
		MVideoManager()->InvalidateRect(rect);
		MVideoManager()->UpdateView(rect.GetLeft(), rect.GetTop(), rect.GetWidth(), rect.GetHeight());
	}
}

// FUNCTION: LEGO1 0x100ba1e0
void MxStillPresenter::ParseExtra()
{
	MxPresenter::ParseExtra();

	if (m_action->GetFlags() & MxDSAction::c_bit5) {
		SetBit3(TRUE);
	}

	MxU16 extraLength;
	char* extraData;
	m_action->GetExtra(extraLength, extraData);

	if (extraLength & MAXWORD) {
		char extraCopy[512];
		memcpy(extraCopy, extraData, extraLength & MAXWORD);
		extraCopy[extraLength & MAXWORD] = '\0';

		char output[512];
		if (KeyValueStringParse(output, g_strVISIBILITY, extraCopy)) {
			if (strcmpi(output, "FALSE") == 0) {
				Enable(FALSE);
			}
		}

		if (KeyValueStringParse(output, g_strBmpIsmap, extraCopy)) {
			SetBit4(TRUE);
			SetBit1(FALSE);
			SetBit2(FALSE);
		}
	}
}

// FUNCTION: LEGO1 0x100ba2c0
MxStillPresenter* MxStillPresenter::Clone()
{
	MxResult result = FAILURE;
	MxStillPresenter* presenter = new MxStillPresenter;

	if (presenter) {
		if (presenter->AddToManager() == SUCCESS) {
			MxDSAction* action = GetAction()->Clone();

			if (action && presenter->StartAction(NULL, action) == SUCCESS) {
				presenter->SetBit0(GetBit0());
				presenter->SetBit1(GetBit1());
				presenter->SetBit2(GetBit2());
				presenter->SetBit3(GetBit3());
				presenter->SetBit4(GetBit4());

				if (m_bitmap) {
					presenter->m_bitmap = new MxBitmap;

					if (!presenter->m_bitmap || presenter->m_bitmap->ImportBitmap(m_bitmap) != SUCCESS) {
						goto done;
					}
				}

				if (m_unk0x58) {
					presenter->m_unk0x58 = MxDisplaySurface::CopySurface(m_unk0x58);
				}

				if (m_alpha) {
					presenter->m_alpha = new MxVideoPresenter::AlphaMask(*m_alpha);
				}

				result = SUCCESS;
			}
		}
	}

done:
	if (result != SUCCESS) {
		delete presenter;
		presenter = NULL;
	}

	return presenter;
}
