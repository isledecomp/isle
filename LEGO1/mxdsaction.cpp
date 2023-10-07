#include "mxdsaction.h"

#include "mxomni.h"
#include "mxtimer.h"
#include "legoutil.h"

#include <float.h>
#include <limits.h>

DECOMP_SIZE_ASSERT(MxDSAction, 0x94)

// GLOBAL OFFSET: LEGO1 0x10101410
MxU16 g_unkSep = TWOCC(',', ' ');

// OFFSET: LEGO1 0x100ad810
MxDSAction::MxDSAction()
{
  this->m_flags = 32;
  this->m_startTime = INT_MIN;
  this->m_extraData = NULL;
  this->m_extraLength = 0;
  this->m_duration = INT_MIN;
  this->m_loopCount = -1;

  this->SetType(MxDSType_Action);
  this->m_location.Fill(FLT_MAX);
  this->m_direction.Fill(FLT_MAX);
  this->m_up.Fill(FLT_MAX);
  this->m_unk84 = 0;
  this->m_unk88 = 0;
  this->m_omni = NULL;
  this->m_someTimingField = INT_MIN;
}

// OFFSET: LEGO1 0x100ada80
MxDSAction::~MxDSAction()
{
  delete[] this->m_extraData;
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

  AppendData(p_dsAction.m_extraLength, p_dsAction.m_extraData);
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

  totalSizeOnDisk = MxDSObject::GetSizeOnDisk() + 90 + this->m_extraLength;
  this->m_sizeOnDisk = totalSizeOnDisk - MxDSObject::GetSizeOnDisk();

  return totalSizeOnDisk;
}

// OFFSET: LEGO1 0x100adf70
void MxDSAction::Deserialize(char **p_source, MxS16 p_unk24)
{
  MxDSObject::Deserialize(p_source, p_unk24);

  GetScalar(p_source, this->m_flags);
  GetScalar(p_source, this->m_startTime);
  GetScalar(p_source, this->m_duration);
  GetScalar(p_source, this->m_loopCount);
  GetDouble(p_source, this->m_location[0]);
  GetDouble(p_source, this->m_location[1]);
  GetDouble(p_source, this->m_location[2]);
  GetDouble(p_source, this->m_direction[0]);
  GetDouble(p_source, this->m_direction[1]);
  GetDouble(p_source, this->m_direction[2]);
  GetDouble(p_source, this->m_up[0]);
  GetDouble(p_source, this->m_up[1]);
  GetDouble(p_source, this->m_up[2]);

  MxU16 extraLength = GetScalar((MxU16**) p_source);
  if (extraLength) {
    AppendData(extraLength, *p_source);
    *p_source += extraLength;
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
  MxU16 extraLength = p_dsAction.m_extraLength;
  char *extraData = p_dsAction.m_extraData;
  if (extraLength && extraData) {
    if (!this->m_extraData || !strncmp("XXX", this->m_extraData, 3)) {
      delete[] this->m_extraData;
      this->m_extraLength = 0;
      AppendData(extraLength, extraData);
    }
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

// Win32 defines GetCurrentTime to GetTickCount
#undef GetCurrentTime

// OFFSET: LEGO1 0x100adcd0
MxLong MxDSAction::GetCurrentTime()
{
  return Timer()->GetTime() - this->m_someTimingField;
}

// OFFSET: LEGO1 0x100ade60
void MxDSAction::AppendData(MxU16 p_extraLength, const char *p_extraData)
{
  if (this->m_extraData == p_extraData || !p_extraData)
    return;

  if (this->m_extraLength) {
    char *concat = new char[p_extraLength + this->m_extraLength + sizeof(g_unkSep)];
    memcpy(concat, this->m_extraData, this->m_extraLength);

    *(MxU16*) &concat[this->m_extraLength] = g_unkSep;
    memcpy(&concat[this->m_extraLength + sizeof(g_unkSep)], p_extraData, p_extraLength);

    this->m_extraLength += p_extraLength + sizeof(g_unkSep);
    delete[] this->m_extraData;
    this->m_extraData = concat;
  }
  else {
    char *copy = new char[p_extraLength];
    this->m_extraData = copy;

    if (copy) {
      this->m_extraLength = p_extraLength;
      memcpy(copy, p_extraData, p_extraLength);
    }
  }
}
