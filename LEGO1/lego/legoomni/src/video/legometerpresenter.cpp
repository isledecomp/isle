#include "legometerpresenter.h"

#include "decomp.h"
#include "mxbitmap.h"
#include "mxutil.h"

DECOMP_SIZE_ASSERT(LegoMeterPresenter, 0x94)

// GLOBAL: LEGO1 0x1010207c
const char* g_filterIndex = "FILTER_INDEX";

// GLOBAL: LEGO1 0x10102094
const char* g_type = "TYPE";

// GLOBAL: LEGO1 0x10102088
const char* g_leftToRight = "LEFT_TO_RIGHT";

// GLOBAL: LEGO1 0x101020ac
const char* g_rightToLeft = "RIGHT_TO_LEFT";

// GLOBAL: LEGO1 0x1010205c
const char* g_bottomToTop = "BOTTOM_TO_TOP";

// GLOBAL: LEGO1 0x101020c0
const char* g_topToBottom = "TOP_TO_BOTTOM";

// GLOBAL: LEGO1 0x101020c8
const char* g_variable = "VARIABLE";

// FUNCTION: LEGO1 0x10043430
LegoMeterPresenter::LegoMeterPresenter()
{
	m_layout = 0;
	m_unk0x6c = 0;
	m_unk0x84 = 0;
	m_type = 1;
	m_flags &= ~Flag_Bit2;
}

// FUNCTION: LEGO1 0x10043780
LegoMeterPresenter::~LegoMeterPresenter()
{
	delete m_unk0x6c;
}

// FUNCTION: LEGO1 0x10043800
void LegoMeterPresenter::ParseExtra()
{
	char buffer[256];

	MxStillPresenter::ParseExtra();
	*((MxU16*) &buffer[0]) = m_action->GetExtraLength();
	char* extraData = m_action->GetExtraData();

	if (*((MxU16*) &buffer[0])) {
		MxU16 len = *((MxU16*) &buffer[0]);
		memcpy(buffer, extraData, len);
		buffer[len] = '\0';

		char result[256];
		if (KeyValueStringParse(buffer, g_type, result)) {
			if (!strcmpi(result, g_leftToRight)) {
				m_layout = 0;
			}
			else if (!strcmpi(result, g_rightToLeft)) {
				m_layout = 1;
			}
			else if (!strcmpi(result, g_bottomToTop)) {
				m_layout = 2;
			}
			else if (!strcmpi(result, g_topToBottom)) {
				m_layout = 3;
			}
		}

		if (KeyValueStringParse(buffer, g_filterIndex, result)) {
			m_type = atoi(result);
		}

		if (KeyValueStringParse(buffer, g_variable, result)) {
			m_variable = result;
		}
		else {
			EndAction();
		}
	}
	else {
		EndAction();
	}
}

// FUNCTION: LEGO1 0x10043990
void LegoMeterPresenter::StreamingTickle()
{
	MxStillPresenter::StreamingTickle();
	m_unk0x6c = new MxU8[m_bitmap->GetBmiStride() * m_bitmap->GetBmiHeightAbs()];
	if (m_unk0x6c == NULL) {
		EndAction();
	}

	memcpy(m_unk0x6c, m_bitmap->GetBitmapData(), m_bitmap->GetBmiStride() * m_bitmap->GetBmiHeightAbs());

	m_unk0x88 = 0;
	m_unk0x8a = 0;
	m_unk0x8c = m_bitmap->GetBmiWidth() - 1;
	m_unk0x8e = m_bitmap->GetBmiHeightAbs() - 1;
}

// FUNCTION: LEGO1 0x10043a30
void LegoMeterPresenter::RepeatingTickle()
{
	FUN_10043a50();
	MxStillPresenter::RepeatingTickle();
}

// STUB: LEGO1 0x10043a50
void LegoMeterPresenter::FUN_10043a50()
{
}
