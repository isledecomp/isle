#include "legometerpresenter.h"

#include "decomp.h"
#include "define.h"
#include "mxbitmap.h"
#include "mxdsaction.h"
#include "mxmisc.h"
#include "mxutilities.h"
#include "mxvariabletable.h"

#include <assert.h>

DECOMP_SIZE_ASSERT(LegoMeterPresenter, 0x94)

// FUNCTION: LEGO1 0x10043430
// FUNCTION: BETA10 0x10097570
LegoMeterPresenter::LegoMeterPresenter()
{
	m_meterPixels = NULL;
	m_fillColor = 1;
	m_curPercent = 0;
	m_layout = e_leftToRight;
	m_flags.m_bit1 = FALSE;
}

// FUNCTION: LEGO1 0x10043780
// FUNCTION: BETA10 0x1009764a
LegoMeterPresenter::~LegoMeterPresenter()
{
	delete[] m_meterPixels;
}

// FUNCTION: LEGO1 0x10043800
// FUNCTION: BETA10 0x100976ec
void LegoMeterPresenter::ParseExtra()
{
	MxStillPresenter::ParseExtra();

	MxU16 extraLength;
	char* extraData;
	m_action->GetExtra(extraLength, extraData);

	if (extraLength) {
		char extraCopy[256];
		memcpy(extraCopy, extraData, extraLength);
		extraCopy[extraLength] = '\0';

		char output[256];
		if (KeyValueStringParse(output, g_strTYPE, extraCopy)) {
			if (!strcmpi(output, g_strLEFT_TO_RIGHT)) {
				m_layout = e_leftToRight;
			}
			else if (!strcmpi(output, g_strRIGHT_TO_LEFT)) {
				m_layout = e_rightToLeft;
			}
			else if (!strcmpi(output, g_strBOTTOM_TO_TOP)) {
				m_layout = e_bottomToTop;
			}
			else if (!strcmpi(output, g_strTOP_TO_BOTTOM)) {
				m_layout = e_topToBottom;
			}
		}

		if (KeyValueStringParse(output, g_strFILLER_INDEX, extraCopy)) {
			m_fillColor = atoi(output);
		}

		if (KeyValueStringParse(output, g_strVARIABLE, extraCopy)) {
			m_variable = output;
		}
		else {
			assert(0);
			EndAction();
		}
	}
	else {
		EndAction();
	}
}

// FUNCTION: LEGO1 0x10043990
// FUNCTION: BETA10 0x10097917
void LegoMeterPresenter::StreamingTickle()
{
	MxStillPresenter::StreamingTickle();

	m_meterPixels = new MxU8[m_frameBitmap->GetDataSize()];
	if (m_meterPixels == NULL) {
		assert(0);
		EndAction();
	}

	memcpy(m_meterPixels, m_frameBitmap->GetImage(), m_frameBitmap->GetDataSize());

	m_meterRect.SetLeft(0);
	m_meterRect.SetTop(0);
	m_meterRect.SetRight(m_frameBitmap->GetBmiWidth() - 1);
	m_meterRect.SetBottom(m_frameBitmap->GetBmiHeightAbs() - 1);
}

// FUNCTION: LEGO1 0x10043a30
// FUNCTION: BETA10 0x10097a1a
void LegoMeterPresenter::RepeatingTickle()
{
	DrawMeter();
	MxStillPresenter::RepeatingTickle();
}

// FUNCTION: LEGO1 0x10043a50
// FUNCTION: BETA10 0x10097a40
void LegoMeterPresenter::DrawMeter()
{
	const char* strval = VariableTable()->GetVariable(m_variable.GetData());
	MxFloat percent = atof(strval);
	MxS16 row, leftRightCol, bottomTopCol, leftRightEnd, bottomTopEnd;

	if (strval != NULL && m_curPercent != percent) {
		m_curPercent = percent;

		// DECOMP: This clamp is retail only
		if (percent > 0.99) {
			m_curPercent = 0.99f;
		}
		else if (percent < 0.0) {
			m_curPercent = 0.0f;
		}

		// Copy the previously drawn meter back into the bitmap
		memcpy(m_frameBitmap->GetImage(), m_meterPixels, m_frameBitmap->GetDataSize());

		switch (m_layout) {
		case e_leftToRight:
			leftRightEnd = m_meterRect.GetWidth() * m_curPercent;

			for (row = m_meterRect.GetTop(); row < m_meterRect.GetBottom(); row++) {
				MxU8* line = m_frameBitmap->GetStart(m_meterRect.GetLeft(), row);

				for (leftRightCol = 0; leftRightCol < leftRightEnd; leftRightCol++, line++) {
					if (*line) {
						*line = m_fillColor;
					}
				}
			}
			break;
		case e_bottomToTop:
			bottomTopEnd = m_meterRect.GetBottom() - (MxS16) (m_meterRect.GetHeight() * m_curPercent);

			for (row = m_meterRect.GetBottom(); row > bottomTopEnd; row--) {
				MxU8* line = m_frameBitmap->GetStart(m_meterRect.GetLeft(), row);

				for (bottomTopCol = 0; bottomTopCol < m_meterRect.GetWidth(); bottomTopCol++, line++) {
					if (*line) {
						*line = m_fillColor;
					}
				}
			}
			// break;
		default:
			// The other two fill options are not implemented.
			break;
		}
	}
}
