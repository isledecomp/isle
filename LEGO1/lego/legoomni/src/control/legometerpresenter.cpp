#include "legometerpresenter.h"

#include "decomp.h"
#include "define.h"
#include "mxbitmap.h"
#include "mxdsaction.h"
#include "mxutilities.h"

DECOMP_SIZE_ASSERT(LegoMeterPresenter, 0x94)

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
		if (KeyValueStringParse(extraCopy, g_strTYPE, output)) {
			if (!strcmpi(output, g_strLEFT_TO_RIGHT)) {
				m_layout = 0;
			}
			else if (!strcmpi(output, g_strRIGHT_TO_LEFT)) {
				m_layout = 1;
			}
			else if (!strcmpi(output, g_strBOTTOM_TO_TOP)) {
				m_layout = 2;
			}
			else if (!strcmpi(output, g_strTOP_TO_BOTTOM)) {
				m_layout = 3;
			}
		}

		if (KeyValueStringParse(extraCopy, g_strFILLER_INDEX, output)) {
			m_type = atoi(output);
		}

		if (KeyValueStringParse(extraCopy, g_strVARIABLE, output)) {
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
	m_unk0x6c = new MxU8[m_frameBitmap->GetBmiStride() * m_frameBitmap->GetBmiHeightAbs()];
	if (m_unk0x6c == NULL) {
		EndAction();
	}

	memcpy(m_unk0x6c, m_frameBitmap->GetImage(), m_frameBitmap->GetBmiStride() * m_frameBitmap->GetBmiHeightAbs());

	m_unk0x88 = 0;
	m_unk0x8a = 0;
	m_unk0x8c = m_frameBitmap->GetBmiWidth() - 1;
	m_unk0x8e = m_frameBitmap->GetBmiHeightAbs() - 1;
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
