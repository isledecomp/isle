#include "mxvideoparam.h"

#include "decomp.h"

#include <stdlib.h>
#include <string.h>

DECOMP_SIZE_ASSERT(MxVideoParam, 0x24)

// FUNCTION: LEGO1 0x100bec70
// FUNCTION: BETA10 0x1012db3e
MxVideoParam::MxVideoParam()
{
	m_rect = MxRect32(0, 0, 640, 480);
	m_palette = NULL;
	m_backBuffers = 0;
	m_unk0x1c = 0;
	m_deviceId = NULL;
}

// FUNCTION: LEGO1 0x100beca0
// FUNCTION: BETA10 0x1012dbb1
MxVideoParam::MxVideoParam(MxRect32& p_rect, MxPalette* p_palette, MxULong p_backBuffers, MxVideoParamFlags& p_flags)
{
	m_rect = p_rect;
	m_palette = p_palette;
	m_backBuffers = p_backBuffers;
	m_flags = p_flags;
	m_unk0x1c = 0;
	m_deviceId = NULL;
}

// FUNCTION: LEGO1 0x100becf0
// FUNCTION: BETA10 0x1012dc1e
MxVideoParam::MxVideoParam(MxVideoParam& p_videoParam)
{
	m_rect = p_videoParam.m_rect;
	m_palette = p_videoParam.m_palette;
	m_backBuffers = p_videoParam.m_backBuffers;
	m_flags = p_videoParam.m_flags;
	m_unk0x1c = p_videoParam.m_unk0x1c;
	m_deviceId = NULL;
	SetDeviceName(p_videoParam.m_deviceId);
}

// FUNCTION: LEGO1 0x100bed50
// FUNCTION: BETA10 0x1012dca3
MxVideoParam::~MxVideoParam()
{
	if (m_deviceId != NULL) {
		delete[] m_deviceId;
	}
}

// FUNCTION: LEGO1 0x100bed70
// FUNCTION: BETA10 0x1012dce1
void MxVideoParam::SetDeviceName(char* p_deviceId)
{
	if (m_deviceId != NULL) {
		delete[] m_deviceId;
	}

	if (p_deviceId != NULL) {
		m_deviceId = new char[strlen(p_deviceId) + 1];

		if (m_deviceId != NULL) {
			strcpy(m_deviceId, p_deviceId);
		}
	}
	else {
		m_deviceId = NULL;
	}
}

// FUNCTION: LEGO1 0x100bede0
// FUNCTION: BETA10 0x1012dd76
MxVideoParam& MxVideoParam::operator=(const MxVideoParam& p_videoParam)
{
	m_rect = p_videoParam.m_rect;
	m_palette = p_videoParam.m_palette;
	m_backBuffers = p_videoParam.m_backBuffers;
	m_flags = p_videoParam.m_flags;
	m_unk0x1c = p_videoParam.m_unk0x1c;
	SetDeviceName(p_videoParam.m_deviceId);

	return *this;
}
