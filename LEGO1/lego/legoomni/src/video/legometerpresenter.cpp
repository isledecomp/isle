#include "legometerpresenter.h"

#include "decomp.h"
#include "mxbitmap.h"
#include "mxutil.h"

// GLOBAL: LEGO1 0x1010207c
const char* g_FILTER_INDEX = "FILTER_INDEX";

// GLOBAL: LEGO1 0x10102094
const char* g_TYPE = "TYPE";

// GLOBAL: LEGO1 0x10102088
const char* g_LEFT_TO_RIGHT = "LEFT_TO_RIGHT";

// GLOBAL: LEGO1 0x101020ac
const char* g_RIGHT_TO_LEFT = "RIGHT_TO_LEFT";

// GLOBAL: LEGO1 0x1010205c
const char* g_BOTTOM_TO_TOP = "BOTTOM_TO_TOP";

// GLOBAL: LEGO1 0x101020c0
const char* g_TOP_TO_BOTTOM = "TOP_TO_BOTTOM";

// GLOBAL: LEGO1 0x101020c8
const char* g_VARIABLE = "VARIABLE";

// Uncomment when member class variables are fleshed out.
DECOMP_SIZE_ASSERT(LegoMeterPresenter, 0x94); // 0x1000a163

// FUNCTION: LEGO1 0x10043430
LegoMeterPresenter::LegoMeterPresenter()
{
	m_layout = 0;
	m_flags &= ~Flag_Bit2;
	m_type = 1;
	m_unk0x6c = 0;
	m_unk0x84 = 0;
}

// FUNCTION: LEGO1 0x10043800
void LegoMeterPresenter::ParseExtra()
{
	MxStillPresenter::ParseExtra();

	if (m_action->GetExtraLength()) {
		char buffer[256];
		char result[256];
		*((MxU16*) &result[0]) = m_action->GetExtraLength();

		memcpy(buffer, m_action->GetExtraData(), *((MxU16*) &result[0]));

		if (KeyValueStringParse(buffer, g_TYPE, result)) {
			if (!strcmp(result, g_LEFT_TO_RIGHT)) {
				m_layout = 0;
			}
			else if (!strcmp(result, g_RIGHT_TO_LEFT)) {
				m_layout = 1;
			}
			else if (!strcmp(result, g_BOTTOM_TO_TOP)) {
				m_layout = 2;
			}
			else if (!strcmp(result, g_TOP_TO_BOTTOM)) {
				m_layout = 3;
			}
		}

		if (KeyValueStringParse(buffer, g_FILTER_INDEX, result)) {
			m_type = atoi(result);
		}

		if (KeyValueStringParse(buffer, g_VARIABLE, result)) {
			m_variable = result;
			return;
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
	m_unk0x6c = new MxU8[((m_bitmap->GetBmiWidth() + 3) & -4) * m_bitmap->GetBmiHeightAbs()];
	if (m_unk0x6c == NULL) {
		EndAction();
	}

	memcpy(m_unk0x6c, m_bitmap->GetBitmapData(), ((m_bitmap->GetBmiWidth() + 3) & -4) * m_bitmap->GetBmiHeightAbs());
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
