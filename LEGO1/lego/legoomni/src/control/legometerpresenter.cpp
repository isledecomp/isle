#include "legometerpresenter.h"

#include "decomp.h"
#include "mxbitmap.h"
#include "mxutilities.h"

DECOMP_SIZE_ASSERT(LegoMeterPresenter, 0x94)

// GLOBAL: LEGO1 0x1010207c
// STRING: LEGO1 0x10101fb4
const char* g_filterIndex = "FILLER_INDEX";

// GLOBAL: LEGO1 0x10102094
// STRING: LEGO1 0x10101f70
const char* g_type = "TYPE";

// GLOBAL: LEGO1 0x10102088
// STRING: LEGO1 0x10101f94
const char* g_leftToRight = "LEFT_TO_RIGHT";

// GLOBAL: LEGO1 0x101020ac
// STRING: LEGO1 0x10101f28
const char* g_rightToLeft = "RIGHT_TO_LEFT";

// GLOBAL: LEGO1 0x1010205c
// STRING: LEGO1 0x10102000
const char* g_bottomToTop = "BOTTOM_TO_TOP";

// GLOBAL: LEGO1 0x101020c0
// STRING: LEGO1 0x10101f00
const char* g_topToBottom = "TOP_TO_BOTTOM";

// GLOBAL: LEGO1 0x101020c8
// STRING: LEGO1 0x10101ee4
const char* g_variable = "VARIABLE";

// FUNCTION: LEGO1 0x10043430
LegoMeterPresenter::LegoMeterPresenter()
{
	m_layout = 0;
	m_unk0x6c = 0;
	m_unk0x84 = 0;
	m_type = 1;
	SetBit1(FALSE);
}

// FUNCTION: LEGO1 0x10043780
LegoMeterPresenter::~LegoMeterPresenter()
{
	delete m_unk0x6c;
}

// FUNCTION: LEGO1 0x10043800
void LegoMeterPresenter::ParseExtra()
{
	MxStillPresenter::ParseExtra();

	MxU16 extraLength;
	char* extraData;
	m_action->GetExtra(extraLength, extraData);

	if (extraLength & MAXWORD) {
		char extraCopy[256];
		memcpy(extraCopy, extraData, extraLength & MAXWORD);
		extraCopy[extraLength & MAXWORD] = '\0';

		char output[256];
		if (KeyValueStringParse(extraCopy, g_type, output)) {
			if (!strcmpi(output, g_leftToRight)) {
				m_layout = 0;
			}
			else if (!strcmpi(output, g_rightToLeft)) {
				m_layout = 1;
			}
			else if (!strcmpi(output, g_bottomToTop)) {
				m_layout = 2;
			}
			else if (!strcmpi(output, g_topToBottom)) {
				m_layout = 3;
			}
		}

		if (KeyValueStringParse(extraCopy, g_filterIndex, output)) {
			m_type = atoi(output);
		}

		if (KeyValueStringParse(extraCopy, g_variable, output)) {
			m_variable = output;
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
