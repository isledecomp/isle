#include "mxstillpresenter.h"

#include "decomp.h"
#include "define.h"
#include "legoomni.h"

DECOMP_SIZE_ASSERT(MxStillPresenter, 0x6c);

// 0x10101eb0
const char* g_strBMP_ISMAP = "BMP_ISMAP";

// OFFSET: LEGO1 0x100ba1e0
void MxStillPresenter::ParseExtra()
{
	MxPresenter::ParseExtra();

	if (m_action->GetFlags() & MxDSAction::Flag_Bit5)
		m_flags |= 0x8;

	MxU32 len = m_action->GetExtraLength();

	if (len == 0)
		return;

  len &= MAXWORD;

	char buf[512];
	memcpy(buf, m_action->GetExtraData(), len);
	buf[len] = '\0';

	char output[512];
	if (KeyValueStringParse(output, g_strVISIBILITY, buf)) {
		if (strcmpi(output, "FALSE") == 0) {
			Enable(FALSE);
		}
	}

	if (KeyValueStringParse(output, g_strBMP_ISMAP, buf)) {
		m_flags |= 0x10;
		m_flags &= ~0x2;
		m_flags &= ~0x4;
	}
}
