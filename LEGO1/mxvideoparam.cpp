#include "mxvideoparam.h"

#include <stdlib.h>
#include <string.h>

// OFFSET: LEGO1 0x100bec70
MxVideoParam::MxVideoParam()
{
  this->m_rect.m_right = 640;
  this->m_rect.m_bottom = 480;
  this->m_rect.m_left = 0;
  this->m_rect.m_top = 0;
  this->m_palette = 0;
  this->m_backBuffers = 0;
  this->m_unk1c = 0;
  this->m_deviceId = 0;
}

// OFFSET: LEGO1 0x100beca0
MxVideoParam::MxVideoParam(COMPAT_CONST MxRect32 &p_rect, MxPalette *p_pal, MxULong p_backBuffers, COMPAT_CONST MxVideoParamFlags &p_flags)
{
  this->m_rect.m_left = p_rect.m_left;
  this->m_rect.m_top = p_rect.m_top;
  this->m_rect.m_right = p_rect.m_right;
  this->m_rect.m_bottom = p_rect.m_bottom;
  this->m_palette = p_pal;
  this->m_backBuffers = p_backBuffers;
  this->m_flags = p_flags;
  this->m_unk1c = 0;
  this->m_deviceId = NULL;
}

// OFFSET: LEGO1 0x100becf0
MxVideoParam::MxVideoParam(MxVideoParam &p_videoParam)
{
  this->m_rect.m_left = p_videoParam.m_rect.m_left;
  this->m_rect.m_top = p_videoParam.m_rect.m_top;
  this->m_rect.m_right = p_videoParam.m_rect.m_right;
  this->m_rect.m_bottom = p_videoParam.m_rect.m_bottom;
  this->m_palette = p_videoParam.m_palette;
  this->m_backBuffers = p_videoParam.m_backBuffers;
  this->m_flags = p_videoParam.m_flags;
  this->m_unk1c = p_videoParam.m_unk1c;
  this->m_deviceId = NULL;
  SetDeviceName(p_videoParam.m_deviceId);
}

// OFFSET: LEGO1 0x100bede0
MxVideoParam &MxVideoParam::operator=(const MxVideoParam &p_videoParam)
{
  this->m_rect.m_left = p_videoParam.m_rect.m_left;
  this->m_rect.m_top = p_videoParam.m_rect.m_top;
  this->m_rect.m_right = p_videoParam.m_rect.m_right;
  this->m_rect.m_bottom = p_videoParam.m_rect.m_bottom;
  this->m_palette = p_videoParam.m_palette;
  this->m_backBuffers = p_videoParam.m_backBuffers;
  this->m_flags = p_videoParam.m_flags;
  this->m_unk1c = p_videoParam.m_unk1c;
  SetDeviceName(p_videoParam.m_deviceId);

  return *this;
}

// OFFSET: LEGO1 0x100bed70
void MxVideoParam::SetDeviceName(char *id)
{
  if (this->m_deviceId != 0)
    free(this->m_deviceId);

  if (id != 0)
  {
    this->m_deviceId = (char *)malloc(strlen(id) + 1);

    if (this->m_deviceId != 0) {
      strcpy(this->m_deviceId, id);
    }
  }
  else {
    this->m_deviceId = 0;
  }
}

// OFFSET: LEGO1 0x100bed50
MxVideoParam::~MxVideoParam()
{
  if (this->m_deviceId != 0)
    free(this->m_deviceId);
}
