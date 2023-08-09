#include "mxdsaction.h"

#include <float.h>
#include <limits.h>

// OFFSET: LEGO1 0x100ad810
MxDSAction::MxDSAction()
{
  this->m_flags = 32;
  this->m_startTime = INT_MIN;
  this->m_unk7c = NULL;
  this->m_unk80 = 0;
  this->m_duration = INT_MIN;
  this->m_loopCount = -1;

  this->SetType(MxDSType_Action);

  {
    float value = FLT_MAX;
    this->m_location.EqualsScalar(&value);
  }

  {
    float value = FLT_MAX;
    this->m_direction.EqualsScalar(&value);
  }

  {
    float value = FLT_MAX;
    this->m_up.EqualsScalar(&value);
  }

  this->m_unk84 = 0;
  this->m_unk88 = 0;
  this->m_omni = NULL;
  this->m_someTimingField = INT_MIN;
}

// OFFSET: LEGO1 0x100ada80
MxDSAction::~MxDSAction()
{
  delete this->m_unk7c;
}

// OFFSET: LEGO1 0x100adaf0
void MxDSAction::CopyFrom(MxDSAction &p_dsAction)
{
  this->SetObjectId(p_dsAction.GetObjectId());
  this->m_flags = p_dsAction.m_flags;
  this->m_startTime = p_dsAction.m_startTime;
  this->m_duration = p_dsAction.m_duration;
  this->m_loopCount = p_dsAction.m_loopCount;

  this->m_location.CopyFrom(p_dsAction.m_location);
  this->m_direction.CopyFrom(p_dsAction.m_direction);
  this->m_up.CopyFrom(p_dsAction.m_up);

  FUN_100ADE60(p_dsAction.m_unk80, p_dsAction.m_unk7c);
  this->m_unk84 = p_dsAction.m_unk84;
  this->m_unk88 = p_dsAction.m_unk88;
  this->m_omni = p_dsAction.m_omni;
  this->m_someTimingField = p_dsAction.m_someTimingField;
}

// OFFSET: LEGO1 0x100adc10
MxDSAction &MxDSAction::operator=(MxDSAction &p_dsAction)
{
  if (this == &p_dsAction)
    return *this;

  MxDSObject::operator=(p_dsAction);
  this->CopyFrom(p_dsAction);
  return *this;
}

// OFFSET: LEGO1 0x100adbe0
MxU32 MxDSAction::GetSizeOnDisk()
{
  MxU32 totalSizeOnDisk;

  totalSizeOnDisk = MxDSObject::GetSizeOnDisk() + 90 + this->m_unk80;
  this->m_sizeOnDisk = totalSizeOnDisk - MxDSObject::GetSizeOnDisk();

  return totalSizeOnDisk;
}

// OFFSET: LEGO1 0x100adf70
void MxDSAction::Deserialize(char **p_source, MxS16 p_unk24)
{
  MxDSObject::Deserialize(p_source, p_unk24);

  this->m_flags = *(DWORD*) *p_source;
  *p_source += sizeof(DWORD);
  this->m_startTime = *(DWORD*) *p_source;
  *p_source += sizeof(DWORD);
  this->m_duration = *(MxLong*) *p_source;
  *p_source += sizeof(MxLong);
  this->m_loopCount = *(MxS32*) *p_source;
  *p_source += sizeof(MxS32);
  this->m_location[0] = *(double*) *p_source;
  *p_source += sizeof(double);
  this->m_location[1] = *(double*) *p_source;
  *p_source += sizeof(double);
  this->m_location[2] = *(double*) *p_source;
  *p_source += sizeof(double);
  this->m_direction[0] = *(double*) *p_source;
  *p_source += sizeof(double);
  this->m_direction[1] = *(double*) *p_source;
  *p_source += sizeof(double);
  this->m_direction[2] = *(double*) *p_source;
  *p_source += sizeof(double);
  this->m_up[0] = *(double*) *p_source;
  *p_source += sizeof(double);
  this->m_up[1] = *(double*) *p_source;
  *p_source += sizeof(double);
  this->m_up[2] = *(double*) *p_source;
  *p_source += sizeof(double);

  MxU16 extralen = *(MxU16*) *p_source;
  *p_source += sizeof(MxU16);
  if (extralen) {
    FUN_100ADE60(extralen, *p_source);
    *p_source += extralen;
  }
}

// OFFSET: LEGO1 0x100ad940
MxLong MxDSAction::GetDuration()
{
  return this->m_duration;
}

// OFFSET: LEGO1 0x100ad950
void MxDSAction::SetDuration(MxLong p_duration)
{
  this->m_duration = p_duration;
}

// OFFSET: LEGO1 0x100adc40
MxDSAction *MxDSAction::Clone()
{
  MxDSAction *clone = new MxDSAction();

  if (clone)
    *clone = *this;

  return clone;
}

// OFFSET: LEGO1 0x100add00
void MxDSAction::MergeFrom(MxDSAction &p_dsAction)
{
  if (p_dsAction.m_startTime != INT_MIN)
    this->m_startTime = p_dsAction.m_startTime;

  if (p_dsAction.GetDuration() != INT_MIN)
    this->m_duration = p_dsAction.GetDuration();

  if (p_dsAction.m_loopCount != -1)
    this->m_loopCount = p_dsAction.m_loopCount;

  if (p_dsAction.m_location[0] != FLT_MAX)
    this->m_location[0] = p_dsAction.m_location[0];
  if (p_dsAction.m_location[1] != FLT_MAX)
    this->m_location[1] = p_dsAction.m_location[1];
  if (p_dsAction.m_location[2] != FLT_MAX)
    this->m_location[2] = p_dsAction.m_location[2];

  if (p_dsAction.m_direction[0] != FLT_MAX)
    this->m_direction[0] = p_dsAction.m_direction[0];
  if (p_dsAction.m_direction[1] != FLT_MAX)
    this->m_direction[1] = p_dsAction.m_direction[1];
  if (p_dsAction.m_direction[2] != FLT_MAX)
    this->m_direction[2] = p_dsAction.m_direction[2];

  if (p_dsAction.m_up[0] != FLT_MAX)
    this->m_up[0] = p_dsAction.m_up[0];
  if (p_dsAction.m_up[1] != FLT_MAX)
    this->m_up[1] = p_dsAction.m_up[1];
  if (p_dsAction.m_up[2] != FLT_MAX)
    this->m_up[2] = p_dsAction.m_up[2];

  // TODO
  if (p_dsAction.m_unk80 &&
      p_dsAction.m_unk7c &&
      *p_dsAction.m_unk7c &&
      !strncmp("XXX", (const char*) p_dsAction.m_unk7c, 3))
  {
    delete this->m_unk7c;
    this->m_unk80 = 0;
    FUN_100ADE60(p_dsAction.m_unk80, p_dsAction.m_unk7c);
  }
}

// OFFSET: LEGO1 0x100ad960
MxBool MxDSAction::HasId(MxU32 p_objectId)
{
  return this->GetObjectId() == p_objectId;
}

// OFFSET: LEGO1 0x100ada40
void MxDSAction::SetSomeTimingField(MxLong p_someTimingField)
{
  this->m_someTimingField = p_someTimingField;
}

// OFFSET: LEGO1 0x100ada50
MxLong MxDSAction::GetSomeTimingField()
{
  return this->m_someTimingField;
}

// OFFSET: LEGO1 0x100adcd0
MxLong MxDSAction::GetCurrentTime()
{
  return Timer()->GetTime() - this->m_someTimingField;
}

// OFFSET: LEGO1 0x100ade60 STUB
void MxDSAction::FUN_100ADE60(MxU16 p_length, void *p_data)
{
  // TOOD
}
