#include "mxvideopresenter.h"

#include "mxautolocker.h"
#include "mxdsmediaaction.h"
#include "mxregioncursor.h"
#include "mxvideomanager.h"

DECOMP_SIZE_ASSERT(MxVideoPresenter, 0x64);
DECOMP_SIZE_ASSERT(MxVideoPresenter::AlphaMask, 0xc);

// FUNCTION: LEGO1 0x1000c700
void MxVideoPresenter::LoadHeader(MxStreamChunk* p_chunk)
{
	// Empty
}

// FUNCTION: LEGO1 0x1000c710
void MxVideoPresenter::CreateBitmap()
{
	// Empty
}

// FUNCTION: LEGO1 0x1000c720
void MxVideoPresenter::LoadFrame(MxStreamChunk* p_chunk)
{
	// Empty
}

// FUNCTION: LEGO1 0x1000c730
void MxVideoPresenter::RealizePalette()
{
	// Empty
}

// FUNCTION: LEGO1 0x1000c740
MxVideoPresenter::~MxVideoPresenter()
{
	Destroy(TRUE);
}

// FUNCTION: LEGO1 0x1000c7a0
void MxVideoPresenter::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x1000c7b0
LPDIRECTDRAWSURFACE MxVideoPresenter::VTable0x78()
{
	return m_unk0x58;
}

// FUNCTION: LEGO1 0x1000c7c0
MxBool MxVideoPresenter::VTable0x7c()
{
	return (m_bitmap != NULL) || (m_alpha != NULL);
}

// FUNCTION: LEGO1 0x1000c7e0
MxS32 MxVideoPresenter::GetWidth()
{
	return m_alpha ? m_alpha->m_width : m_bitmap->GetBmiWidth();
}

// FUNCTION: LEGO1 0x1000c800
MxS32 MxVideoPresenter::GetHeight()
{
	return m_alpha ? m_alpha->m_height : m_bitmap->GetBmiHeightAbs();
}

// FUNCTION: LEGO1 0x100b24f0
MxVideoPresenter::AlphaMask::AlphaMask(const MxBitmap& p_bitmap)
{
	m_width = p_bitmap.GetBmiWidth();
	// DECOMP: ECX becomes word-sized if these are not two separate actions.
	MxLong height = p_bitmap.GetBmiHeightAbs();
	m_height = height;

	MxS32 size = ((m_width * m_height) / 8) + 1;
	m_bitmask = new MxU8[size];
	memset(m_bitmask, 0, size);

	MxU32 biCompression = p_bitmap.GetBmiHeader()->biCompression;
	MxU32 rowsBeforeTop;
	MxU8* bitmapSrcPtr;

	// The goal here is to enable us to walk through the bitmap's rows
	// in order, regardless of the orientation. We want to end up at the
	// start of the first row, which is either at position 0, or at
	// (image_stride * biHeight) - 1.

	// Reminder: Negative biHeight means this is a top-down DIB.
	// Otherwise it is bottom-up.

	if (biCompression == BI_RGB) {
		// DECOMP: I think this must be an OR. If not, the check for
		// biCompression == 16 gets optimized away.
		if (biCompression == BI_RGB_TOPDOWN || p_bitmap.GetBmiHeight() < 0) {
			rowsBeforeTop = 0;
		}
		else {
			rowsBeforeTop = p_bitmap.GetBmiHeightAbs();
			rowsBeforeTop--;
		}

		goto seek_to_last_row;
	}
	else if (biCompression == BI_RGB_TOPDOWN) {
		// DECOMP: This is the only condition where we skip the
		// calculation below.
		bitmapSrcPtr = p_bitmap.GetBitmapData();
	}
	else {
		if (p_bitmap.GetBmiHeight() < 0) {
			rowsBeforeTop = 0;
		}
		else {
			rowsBeforeTop = p_bitmap.GetBmiHeightAbs();
			rowsBeforeTop--;
		}

	// TODO: would prefer not to use goto if we can figure this structure out
	seek_to_last_row:
		bitmapSrcPtr = p_bitmap.GetBmiStride() * rowsBeforeTop + p_bitmap.GetBitmapData();
	}

	// How many bytes are there for each row of the bitmap?
	// (i.e. the image stride)
	// If this is a bottom-up DIB, we will walk it in reverse.
	// TODO: Same rounding trick as in MxBitmap
	MxS32 rowSeek = ((m_width + 3) & -4);
	if (p_bitmap.GetBmiHeight() < 0)
		rowSeek = -rowSeek;

	// The actual offset into the m_bitmask array. The two for-loops
	// are just for counting the pixels.
	MxS32 offset = 0;

	MxU8* tPtr = bitmapSrcPtr;
	for (MxS32 j = 0; j < m_height; j++) {
		for (MxS32 i = 0; i < m_width; i++) {
			if (*tPtr) {
				// TODO: Second CDQ instruction for abs() should not be there.
				MxU32 shift = abs(offset) & 7;
				m_bitmask[offset / 8] |= (1 << abs((MxS32) shift));
			}
			tPtr++;
			offset++;
		}
		// Seek to the start of the next row
		bitmapSrcPtr += rowSeek;
		tPtr = bitmapSrcPtr;
	}
}

// FUNCTION: LEGO1 0x100b2670
MxVideoPresenter::AlphaMask::AlphaMask(const MxVideoPresenter::AlphaMask& p_alpha)
{
	m_width = p_alpha.m_width;
	m_height = p_alpha.m_height;

	MxS32 size = ((m_width * m_height) / 8) + 1;
	m_bitmask = new MxU8[size];
	memcpy(m_bitmask, p_alpha.m_bitmask, size);
}

// FUNCTION: LEGO1 0x100b26d0
MxVideoPresenter::AlphaMask::~AlphaMask()
{
	if (m_bitmask)
		delete[] m_bitmask;
}

// FUNCTION: LEGO1 0x100b26f0
MxS32 MxVideoPresenter::AlphaMask::IsHit(MxU32 p_x, MxU32 p_y)
{
	if (p_x >= m_width || p_y >= m_height)
		return 0;

	MxS32 pos = p_y * m_width + p_x;
	return m_bitmask[pos / 8] & (1 << abs(abs(pos) & 7)) ? 1 : 0;
}

// FUNCTION: LEGO1 0x100b2760
void MxVideoPresenter::Init()
{
	m_bitmap = NULL;
	m_alpha = NULL;
	m_unk0x5c = 1;
	m_unk0x58 = NULL;
	m_unk0x60 = -1;
	m_flags &= ~Flag_Bit1;

	if (MVideoManager() != NULL) {
		MVideoManager();
		m_flags |= Flag_Bit2;
		m_flags &= ~Flag_Bit3;
	}

	m_flags &= ~Flag_Bit4;
	m_flags &= ~Flag_Bit5;
}

// FUNCTION: LEGO1 0x100b27b0
void MxVideoPresenter::Destroy(MxBool p_fromDestructor)
{
	if (MVideoManager() != NULL)
		MVideoManager()->RemovePresenter(*this);

	if (m_unk0x58) {
		m_unk0x58->Release();
		m_unk0x58 = NULL;
		m_flags &= ~Flag_Bit2;
		m_flags &= ~Flag_Bit3;
	}

	if (MVideoManager() && (m_alpha || m_bitmap)) {
		// MxRect32 rect(m_location, MxSize32(GetWidth(), GetHeight()));
		MxS32 height = GetHeight();
		MxS32 width = GetWidth();
		MxS32 x = m_location.GetX();
		MxS32 y = m_location.GetY();

		MxRect32 rect(x, y, x + width, y + height);
		MVideoManager()->InvalidateRect(rect);
		MVideoManager()->VTable0x34(rect.GetLeft(), rect.GetTop(), rect.GetWidth(), rect.GetHeight());
	}

	delete m_bitmap;
	delete m_alpha;

	Init();

	if (!p_fromDestructor)
		MxMediaPresenter::Destroy(FALSE);
}

// FUNCTION: LEGO1 0x100b28b0
void MxVideoPresenter::NextFrame()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk->GetFlags() & MxDSChunk::Flag_End) {
		m_subscriber->FUN_100b8390(chunk);
		m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
		m_currentTickleState = TickleState_Repeating;
	}
	else {
		LoadFrame(chunk);
		m_subscriber->FUN_100b8390(chunk);
	}
}

// FUNCTION: LEGO1 0x100b2900
MxBool MxVideoPresenter::IsHit(MxS32 p_x, MxS32 p_y)
{
	MxDSAction* action = GetAction();
	if ((action == NULL) || (((action->GetFlags() & MxDSAction::Flag_Bit11) == 0) && !IsEnabled()) ||
		(!m_bitmap && !m_alpha))
		return FALSE;

	if (!m_bitmap)
		return m_alpha->IsHit(p_x - m_location.GetX(), p_y - m_location.GetY());

	MxLong heightAbs = m_bitmap->GetBmiHeightAbs();

	MxLong minX = m_location.GetX();
	MxLong minY = m_location.GetY();

	MxLong maxY = minY + heightAbs;
	MxLong maxX = minX + m_bitmap->GetBmiWidth();

	if (p_x < minX || p_x >= maxX || p_y < minY || p_y >= maxY)
		return FALSE;

	MxU8* pixel;

	MxLong biCompression = m_bitmap->GetBmiHeader()->biCompression;
	MxLong height = m_bitmap->GetBmiHeight();
	MxLong seekRow;

	// DECOMP: Same basic layout as AlphaMask constructor
	// The idea here is to again seek to the correct place in the bitmap's
	// m_data buffer. The x,y args are (most likely) screen x and y, so we
	// need to shift that to coordinates local to the bitmap by removing
	// the MxPresenter location x and y coordinates.
	if (biCompression == BI_RGB) {
		if (biCompression == BI_RGB_TOPDOWN || height < 0) {
			seekRow = p_y - m_location.GetY();
		}
		else {
			height = height > 0 ? height : -height;
			seekRow = height - p_y - 1 + m_location.GetY();
		}
		pixel = m_bitmap->GetBmiStride() * seekRow + m_bitmap->GetBitmapData() - m_location.GetX() + p_x;
	}
	else if (biCompression == BI_RGB_TOPDOWN) {
		pixel = m_bitmap->GetBitmapData();
	}
	else {
		height = height > 0 ? height : -height;
		height--;
		pixel = m_bitmap->GetBmiStride() * height + m_bitmap->GetBitmapData();
	}

	// DECOMP: m_flags is 1 byte, so no enum here
	if (m_flags & 0x10)
		return (MxBool) *pixel;

	if ((GetAction()->GetFlags() & MxDSAction::Flag_Bit4) && *pixel == 0)
		return FALSE;

	return TRUE;
}

inline MxS32 MxVideoPresenter::PrepareRects(MxRect32& p_rectDest, MxRect32& p_rectSrc)
{
	if (p_rectDest.GetTop() > 480 || p_rectDest.GetLeft() > 640 || p_rectSrc.GetTop() > 480 ||
		p_rectSrc.GetLeft() > 640)
		return -1;

	if (p_rectDest.GetBottom() > 480)
		p_rectDest.SetBottom(480);

	if (p_rectDest.GetRight() > 640)
		p_rectDest.SetRight(640);

	if (p_rectSrc.GetBottom() > 480)
		p_rectSrc.SetBottom(480);

	if (p_rectSrc.GetRight() > 640)
		p_rectSrc.SetRight(640);

	MxS32 height = p_rectDest.GetHeight();
	if (height <= 1)
		return -1;

	MxS32 width = p_rectDest.GetWidth();
	if (width <= 1)
		return -1;

	if (p_rectSrc.GetRight() - width - p_rectSrc.GetLeft() == -1 &&
		p_rectSrc.GetBottom() - height - p_rectSrc.GetTop() == -1)
		return 1;

	p_rectSrc.SetRight(p_rectSrc.GetLeft() + width - 1);
	p_rectSrc.SetBottom(p_rectSrc.GetTop() + height - 1);
	return 0;
}

// FUNCTION: LEGO1 0x100b2a70
void MxVideoPresenter::PutFrame()
{
	MxDisplaySurface* displaySurface = MVideoManager()->GetDisplaySurface();
	MxRegion* region = MVideoManager()->GetRegion();
	MxRect32 rect(m_location, MxSize32(GetWidth(), GetHeight()));
	LPDIRECTDRAWSURFACE ddSurface = displaySurface->GetDirectDrawSurface2();

	MxRect32 rectSrc, rectDest;
	if (m_action->GetFlags() & MxDSAction::Flag_Bit5) {
		if (m_unk0x58) {
			// TODO: Match
			rectSrc.SetPoint(MxPoint32(0, 0));
			rectSrc.SetRight(GetWidth());
			rectSrc.SetBottom(GetHeight());

			rectDest.SetPoint(m_location);
			rectDest.SetRight(rectDest.GetLeft() + GetWidth());
			rectDest.SetBottom(rectDest.GetTop() + GetHeight());

			switch (PrepareRects(rectDest, rectSrc)) {
			case 0:
				ddSurface->Blt((LPRECT) &rectDest, m_unk0x58, (LPRECT) &rectSrc, DDBLT_KEYSRC, NULL);
				break;
			case 1:
				ddSurface->BltFast(
					rectDest.GetLeft(),
					rectDest.GetTop(),
					m_unk0x58,
					(LPRECT) &rectSrc,
					DDBLTFAST_SRCCOLORKEY | DDBLTFAST_WAIT
				);
			}
		}
		else {
			displaySurface->VTable0x30(
				m_bitmap,
				0,
				0,
				rect.GetLeft(),
				rect.GetTop(),
				m_bitmap->GetBmiWidth(),
				m_bitmap->GetBmiHeightAbs(),
				TRUE
			);
		}
	}
	else {
		MxRegionCursor cursor(region);
		MxRect32* regionRect;

		while (regionRect = cursor.VTable0x24(rect)) {
			if (regionRect->GetWidth() >= 1 && regionRect->GetHeight() >= 1) {
				if (m_unk0x58) {
					rectSrc.SetLeft(regionRect->GetLeft() - m_location.GetX());
					rectSrc.SetTop(regionRect->GetTop() - m_location.GetY());
					rectSrc.SetRight(rectSrc.GetLeft() + regionRect->GetWidth());
					rectSrc.SetBottom(rectSrc.GetTop() + regionRect->GetHeight());

					rectDest.SetLeft(regionRect->GetLeft());
					rectDest.SetTop(regionRect->GetTop());
					rectDest.SetRight(rectDest.GetLeft() + regionRect->GetWidth());
					rectDest.SetBottom(rectDest.GetTop() + regionRect->GetHeight());
				}

				if (m_action->GetFlags() & MxDSAction::Flag_Bit4) {
					if (m_unk0x58) {
						if (PrepareRects(rectDest, rectSrc) >= 0)
							ddSurface->Blt((LPRECT) &rectDest, m_unk0x58, (LPRECT) &rectSrc, DDBLT_KEYSRC, NULL);
					}
					else {
						displaySurface->VTable0x30(
							m_bitmap,
							regionRect->GetLeft() - m_location.GetX(),
							regionRect->GetTop() - m_location.GetY(),
							regionRect->GetLeft(),
							regionRect->GetTop(),
							regionRect->GetWidth(),
							regionRect->GetHeight(),
							FALSE
						);
					}
				}
				else if (m_unk0x58) {
					if (PrepareRects(rectDest, rectSrc) >= 0)
						ddSurface->Blt((LPRECT) &rectDest, m_unk0x58, (LPRECT) &rectSrc, 0, NULL);
				}
				else {
					displaySurface->VTable0x28(
						m_bitmap,
						regionRect->GetLeft() - m_location.GetX(),
						regionRect->GetTop() - m_location.GetY(),
						regionRect->GetLeft(),
						regionRect->GetTop(),
						regionRect->GetWidth(),
						regionRect->GetHeight()
					);
				}
			}
		}
	}
}

// FUNCTION: LEGO1 0x100b2f60
void MxVideoPresenter::ReadyTickle()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk) {
		LoadHeader(chunk);
		m_subscriber->FUN_100b8390(chunk);
		ParseExtra();
		m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
		m_currentTickleState = TickleState_Starting;
	}
}

// FUNCTION: LEGO1 0x100b2fa0
void MxVideoPresenter::StartingTickle()
{
	MxStreamChunk* chunk = FUN_100b5650();

	if (chunk && m_action->GetElapsedTime() >= chunk->GetTime()) {
		CreateBitmap();
		m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
		m_currentTickleState = TickleState_Streaming;
	}
}

// FUNCTION: LEGO1 0x100b2fe0
void MxVideoPresenter::StreamingTickle()
{
	if (m_action->GetFlags() & MxDSAction::Flag_Bit10) {
		if (!m_currentChunk)
			MxMediaPresenter::StreamingTickle();

		if (m_currentChunk) {
			LoadFrame(m_currentChunk);
			m_currentChunk = NULL;
		}
	}
	else {
		for (MxS16 i = 0; i < m_unk0x5c; i++) {
			if (!m_currentChunk) {
				MxMediaPresenter::StreamingTickle();

				if (!m_currentChunk)
					break;
			}

			if (m_action->GetElapsedTime() < m_currentChunk->GetTime())
				break;

			LoadFrame(m_currentChunk);
			m_subscriber->FUN_100b8390(m_currentChunk);
			m_currentChunk = NULL;
			m_flags |= Flag_Bit1;

			if (m_currentTickleState != TickleState_Streaming)
				break;
		}

		if (m_flags & Flag_Bit1)
			m_unk0x5c = 5;
	}
}

// FUNCTION: LEGO1 0x100b3080
void MxVideoPresenter::RepeatingTickle()
{
	if (IsEnabled()) {
		if (m_action->GetFlags() & MxDSAction::Flag_Bit10) {
			if (!m_currentChunk)
				MxMediaPresenter::RepeatingTickle();

			if (m_currentChunk) {
				LoadFrame(m_currentChunk);
				m_currentChunk = NULL;
			}
		}
		else {
			for (MxS16 i = 0; i < m_unk0x5c; i++) {
				if (!m_currentChunk) {
					MxMediaPresenter::RepeatingTickle();

					if (!m_currentChunk)
						break;
				}

				if (m_action->GetElapsedTime() % m_action->GetLoopCount() < m_currentChunk->GetTime())
					break;

				LoadFrame(m_currentChunk);
				m_currentChunk = NULL;
				m_flags |= Flag_Bit1;

				if (m_currentTickleState != TickleState_Repeating)
					break;
			}

			if (m_flags & Flag_Bit1)
				m_unk0x5c = 5;
		}
	}
}

// FUNCTION: LEGO1 0x100b3130
void MxVideoPresenter::Unk5Tickle()
{
	MxLong sustainTime = ((MxDSMediaAction*) m_action)->GetSustainTime();

	if (sustainTime != -1) {
		if (sustainTime) {
			if (m_unk0x60 == -1)
				m_unk0x60 = m_action->GetElapsedTime();

			if (m_action->GetElapsedTime() >= m_unk0x60 + ((MxDSMediaAction*) m_action)->GetSustainTime()) {
				m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
				m_currentTickleState = TickleState_Done;
			}
		}
		else {
			m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
			m_currentTickleState = TickleState_Done;
		}
	}
}

// FUNCTION: LEGO1 0x100b31a0
MxResult MxVideoPresenter::AddToManager()
{
	MxResult result = FAILURE;

	if (MVideoManager()) {
		result = SUCCESS;
		MVideoManager()->AddPresenter(*this);
	}

	return result;
}

// FUNCTION: LEGO1 0x100b31d0
void MxVideoPresenter::EndAction()
{
	if (m_action) {
		MxMediaPresenter::EndAction();
		MxAutoLocker lock(&m_criticalSection);

		if (m_bitmap) {
			MxLong height = m_bitmap->GetBmiHeightAbs();
			MxLong width = m_bitmap->GetBmiWidth();
			MxS32 x = m_location.GetX();
			MxS32 y = m_location.GetY();

			MxRect32 rect(x, y, x + width, y + height);

			MVideoManager()->InvalidateRect(rect);
		}
	}
}

// FUNCTION: LEGO1 0x100b3280
MxResult MxVideoPresenter::PutData()
{
	MxAutoLocker lock(&m_criticalSection);

	if (IsEnabled() && m_currentTickleState >= TickleState_Streaming && m_currentTickleState <= TickleState_unk5)
		PutFrame();

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100b3300
undefined MxVideoPresenter::VTable0x74()
{
	return 0;
}
