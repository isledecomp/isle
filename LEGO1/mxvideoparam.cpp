#include "mxvideoparam.h"

// OFFSET: LEGO1 0x100bec70
MxVideoParam::MxVideoParam()
{
  this->m_flags = MxVideoParamFlags();
  this->m_right = 640;
  this->m_bottom = 480;
  this->m_left = 0;
  this->m_top = 0;
  this->m_palette = 0;
  this->m_backBuffers = 0;
  this->m_unk1c = 0;
  this->m_deviceId = 0;
}

// OFFSET: LEGO1 0x100becf0
MxVideoParam &MxVideoParam::operator=(const MxVideoParam &other)
{
  m_flags = MxVideoParamFlags();
  m_left = other.m_left;
  m_top = other.m_top;
  m_right = other.m_right;
  m_bottom = other.m_bottom;
  m_palette = other.m_palette;
  m_backBuffers = other.m_backBuffers;
  m_flags = other.m_flags;
  m_unk1c = other.m_unk1c;
  m_deviceId = other.m_deviceId;
  SetDeviceName(other.m_deviceId);

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
