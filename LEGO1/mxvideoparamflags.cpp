#include "mxvideoparamflags.h"

// OFFSET: LEGO1 0x100bec40
MxVideoParamFlags::MxVideoParamFlags()
{
  this->SetFullScreen(0);
  this->SetFlipSurfaces(0);
  this->SetBackBuffers(0);
  this->Set_f1bit3(0);
  this->Set_f1bit4(0);
  this->Set16Bit(0);
  this->SetWideViewAngle(1);
  this->Set_f1bit7(1);
  this->Set_f2bit1(1);
}
