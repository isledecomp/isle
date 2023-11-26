#include "mxvideopresenter.h"

#include "mxautolocker.h"
#include "mxdsmediaaction.h"
#include "mxvideomanager.h"

DECOMP_SIZE_ASSERT(MxVideoPresenter, 0x64);
DECOMP_SIZE_ASSERT(MxVideoPresenter::AlphaMask, 0xc);

// OFFSET: LEGO1 0x1000c700
void MxVideoPresenter::LoadHeader(MxStreamChunk* p_chunk)
{
	// Empty
}

// OFFSET: LEGO1 0x1000c710
void MxVideoPresenter::CreateBitmap()
{
	// Empty
}

// OFFSET: LEGO1 0x1000c720
void MxVideoPresenter::LoadFrame(MxStreamChunk* p_chunk)
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
void MxVideoPresenter::Destroy()
{
	Destroy(FALSE);
}

// OFFSET: LEGO1 0x1000c7b0
LPDIRECTDRAWSURFACE MxVideoPresenter::VTable0x78()
{
	return m_unk58;
}

// OFFSET: LEGO1 0x1000c7c0
MxBool MxVideoPresenter::VTable0x7c()
{
	return (m_bitmap != NULL) || (m_alpha != NULL);
}

// OFFSET: LEGO1 0x1000c7e0
MxS32 MxVideoPresenter::GetWidth()
{
	return m_alpha ? m_alpha->m_width : m_bitmap->GetBmiHeader()->biWidth;
}

// OFFSET: LEGO1 0x1000c800
MxS32 MxVideoPresenter::GetHeight()
{
	return m_alpha ? m_alpha->m_height : m_bitmap->GetBmiHeader()->biHeight;
}

// OFFSET: LEGO1 0x100b24f0
MxVideoPresenter::AlphaMask::AlphaMask(const MxBitmap& p_bitmap)
{
	m_width = p_bitmap.GetBmiWidth();
	// DECOMP: ECX becomes word-sized if these are not two separate actions.
	MxLong _height = p_bitmap.GetBmiHeightAbs();
	m_height = _height;

	MxS32 size = ((m_width * m_height) / 8) + 1;
	m_bitmask = new MxU8[size];
	memset(m_bitmask, 0, size);

	MxU32 biCompression = p_bitmap.GetBmiHeader()->biCompression;
	MxU32 rows_before_top;
	MxU8* bitmap_src_ptr;

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
			rows_before_top = 0;
		}
		else {
			rows_before_top = p_bitmap.GetBmiHeightAbs();
			rows_before_top--;
		}

		goto seek_to_last_row;
	}
	else if (biCompression == BI_RGB_TOPDOWN) {
		// DECOMP: This is the only condition where we skip the
		// calculation below.
		bitmap_src_ptr = p_bitmap.GetBitmapData();
	}
	else {
		if (p_bitmap.GetBmiHeight() < 0) {
			rows_before_top = 0;
		}
		else {
			rows_before_top = p_bitmap.GetBmiHeightAbs();
			rows_before_top--;
		}

	// TODO: would prefer not to use goto if we can figure this structure out
	seek_to_last_row:
		bitmap_src_ptr = p_bitmap.GetBmiStride() * rows_before_top + p_bitmap.GetBitmapData();
	}

	// How many bytes are there for each row of the bitmap?
	// (i.e. the image stride)
	// If this is a bottom-up DIB, we will walk it in reverse.
	// TODO: Same rounding trick as in MxBitmap
	MxS32 row_seek = ((m_width + 3) & -4);
	if (p_bitmap.GetBmiHeight() < 0)
		row_seek = -row_seek;

	// The actual offset into the m_bitmask array. The two for-loops
	// are just for counting the pixels.
	MxS32 offset = 0;

	MxU8* t_ptr = bitmap_src_ptr;
	for (MxS32 j = 0; j < m_height; j++) {
		for (MxS32 i = 0; i < m_width; i++) {
			if (*t_ptr) {
				// TODO: Second CDQ instruction for abs() should not be there.
				MxU32 shift = abs(offset) & 7;
				m_bitmask[offset / 8] |= (1 << abs((MxS32) shift));
			}
			t_ptr++;
			offset++;
		}
		// Seek to the start of the next row
		bitmap_src_ptr += row_seek;
		t_ptr = bitmap_src_ptr;
	}
}

// OFFSET: LEGO1 0x100b2670
MxVideoPresenter::AlphaMask::AlphaMask(const MxVideoPresenter::AlphaMask& p_alpha)
{
	m_width = p_alpha.m_width;
	m_height = p_alpha.m_height;

	MxS32 size = ((m_width * m_height) / 8) + 1;
	m_bitmask = new MxU8[size];
	memcpy(m_bitmask, p_alpha.m_bitmask, size);
}

// OFFSET: LEGO1 0x100b26d0
MxVideoPresenter::AlphaMask::~AlphaMask()
{
	if (m_bitmask)
		delete[] m_bitmask;
}

// OFFSET: LEGO1 0x100b26f0
MxS32 MxVideoPresenter::AlphaMask::IsHit(MxU32 p_x, MxU32 p_y)
{
	if (p_x >= m_width || p_y >= m_height)
		return 0;

	MxS32 pos = p_y * m_width + p_x;
	return m_bitmask[pos / 8] & (1 << abs(abs(pos) & 7)) ? 1 : 0;
}

// OFFSET: LEGO1 0x100b2760
void MxVideoPresenter::Init()
{
	m_bitmap = NULL;
	m_alpha = NULL;
	m_unk5c = 1;
	m_unk58 = NULL;
	m_unk60 = -1;
	m_flags = m_flags & 0xfe;

	if (MVideoManager() != NULL) {
		MVideoManager();
		m_flags = m_flags | 2;
		m_flags = m_flags & 0xfb;
	}

	m_flags = m_flags & 0xf7;
	m_flags = m_flags & 0xef;
}

// OFFSET: LEGO1 0x100b27b0
void MxVideoPresenter::Destroy(MxBool p_fromDestructor)
{
	if (MVideoManager() != NULL)
		MVideoManager()->RemovePresenter(*this);

	if (m_unk58) {
		m_unk58->Release();
		m_unk58 = NULL;
		m_flags = m_flags & 0xfd;
		m_flags = m_flags & 0xfb;
	}

	if (MVideoManager() && (m_alpha || m_bitmap)) {
		MxS32 height = GetHeight();
		MxS32 width = GetWidth();

		MxS32 x = GetLocationX();
		MxS32 y = GetLocationY();
		MxRect32 rect(x, y, x + width, y + height);

		MVideoManager()->InvalidateRect(rect);
		MVideoManager()->vtable0x34(rect.GetLeft(), rect.GetTop(), rect.GetWidth(), rect.GetHeight());
	}

	delete m_bitmap;
	delete m_alpha;

	Init();

	if (!p_fromDestructor)
		MxMediaPresenter::Destroy(FALSE);
}

// OFFSET: LEGO1 0x100b28b0
void MxVideoPresenter::NextFrame()
{
	MxStreamChunk* chunk = NextChunk();

	if (chunk->GetFlags() & MxStreamChunk::Flag_Bit2) {
		m_subscriber->FUN_100b8390(chunk);
		m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
		m_currentTickleState = TickleState_Repeating;
	}
	else {
		LoadFrame(chunk);
		m_subscriber->FUN_100b8390(chunk);
	}
}

// OFFSET: LEGO1 0x100b2900
MxBool MxVideoPresenter::IsHit(MxS32 p_x, MxS32 p_y)
{
	MxDSAction* action = GetAction();
	if ((action == NULL) || (((action->GetFlags() & MxDSAction::Flag_Bit10) == 0) && !IsEnabled()) ||
		(!m_bitmap && !m_alpha))
		return FALSE;

	if (!m_bitmap)
		return m_alpha->IsHit(p_x - GetLocationX(), p_y - GetLocationY());

	MxLong heightAbs = m_bitmap->GetBmiHeightAbs();

	MxLong min_x = GetLocationX();
	MxLong min_y = GetLocationY();

	MxLong max_y = min_y + heightAbs;
	MxLong max_x = min_x + m_bitmap->GetBmiWidth();

	if (p_x < min_x || p_x >= max_x || p_y < min_y || p_y >= max_y)
		return FALSE;

	MxU8* pixel;

	MxLong biCompression = m_bitmap->GetBmiHeader()->biCompression;
	MxLong height = m_bitmap->GetBmiHeight();
	MxLong seek_row;

	// DECOMP: Same basic layout as AlphaMask constructor
	// The idea here is to again seek to the correct place in the bitmap's
	// m_data buffer. The x,y args are (most likely) screen x and y, so we
	// need to shift that to coordinates local to the bitmap by removing
	// the MxPresenter location x and y coordinates.
	if (biCompression == BI_RGB) {
		if (biCompression == BI_RGB_TOPDOWN || height < 0) {
			seek_row = p_y - GetLocationY();
		}
		else {
			height = height > 0 ? height : -height;
			seek_row = height - p_y - 1 + GetLocationY();
		}
		pixel = m_bitmap->GetBmiStride() * seek_row + m_bitmap->GetBitmapData() - GetLocationX() + p_x;
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

// OFFSET: LEGO1 0x100b2a70 STUB
void MxVideoPresenter::VTable0x6c()
{
	// TODO
}

// OFFSET: LEGO1 0x100b2f60
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

// OFFSET: LEGO1 0x100b2fa0
void MxVideoPresenter::StartingTickle()
{
	MxStreamChunk* chunk = FUN_100b5650();

	if (chunk && m_action->GetElapsedTime() >= chunk->GetTime()) {
		CreateBitmap();
		m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
		m_currentTickleState = TickleState_Streaming;
	}
}

// OFFSET: LEGO1 0x100b2fe0
void MxVideoPresenter::StreamingTickle()
{
	if (m_action->GetFlags() & MxDSAction::Flag_Bit9) {
		if (!m_currentChunk)
			MxMediaPresenter::StreamingTickle();

		if (m_currentChunk) {
			LoadFrame(m_currentChunk);
			m_currentChunk = NULL;
		}
	}
	else {
		for (MxS16 i = 0; i < m_unk5c; i++) {
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
			m_unk5c = 5;
	}
}

// OFFSET: LEGO1 0x100b3080
void MxVideoPresenter::RepeatingTickle()
{
	if (IsEnabled()) {
		if (m_action->GetFlags() & MxDSAction::Flag_Bit9) {
			if (!m_currentChunk)
				MxMediaPresenter::RepeatingTickle();

			if (m_currentChunk) {
				LoadFrame(m_currentChunk);
				m_currentChunk = NULL;
			}
		}
		else {
			for (MxS16 i = 0; i < m_unk5c; i++) {
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
				m_unk5c = 5;
		}
	}
}

// OFFSET: LEGO1 0x100b3130
void MxVideoPresenter::Unk5Tickle()
{
	MxLong sustainTime = ((MxDSMediaAction*) m_action)->GetSustainTime();

	if (sustainTime != -1) {
		if (sustainTime) {
			if (m_unk60 == -1)
				m_unk60 = m_action->GetElapsedTime();

			if (m_action->GetElapsedTime() >= m_unk60 + ((MxDSMediaAction*) m_action)->GetSustainTime()) {
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

// OFFSET: LEGO1 0x100b31a0
MxResult MxVideoPresenter::AddToManager()
{
	MxResult result = FAILURE;

	if (MVideoManager()) {
		result = SUCCESS;
		MVideoManager()->AddPresenter(*this);
	}

	return result;
}

// OFFSET: LEGO1 0x100b31d0
void MxVideoPresenter::EndAction()
{
	if (m_action) {
		MxMediaPresenter::EndAction();
		MxAutoLocker lock(&m_criticalSection);

		if (m_bitmap) {
			MxLong height = m_bitmap->GetBmiHeightAbs();
			MxLong width = m_bitmap->GetBmiWidth();
			MxS32 x = m_location.m_x;
			MxS32 y = m_location.m_y;

			MxRect32 rect(x, y, x + width, y + height);

			MVideoManager()->InvalidateRect(rect);
		}
	}
}

// OFFSET: LEGO1 0x100b3280
MxResult MxVideoPresenter::PutData()
{
	MxAutoLocker lock(&m_criticalSection);

	if (IsEnabled() && m_currentTickleState >= TickleState_Streaming && m_currentTickleState <= TickleState_unk5)
		VTable0x6c();

	return SUCCESS;
}

// OFFSET: LEGO1 0x100b3300
undefined MxVideoPresenter::VTable0x74()
{
	return 0;
}
