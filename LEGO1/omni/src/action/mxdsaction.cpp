#include "mxdsaction.h"

#include "mxmisc.h"
#include "mxtimer.h"
#include "mxutilities.h"

#include <float.h>
#include <limits.h>

DECOMP_SIZE_ASSERT(MxDSAction, 0x94)

// GLOBAL: LEGO1 0x10101410
MxU16 g_sep = TWOCC(',', ' ');

// FUNCTION: LEGO1 0x100ad810
MxDSAction::MxDSAction()
{
	this->m_flags = MxDSAction::c_enabled;
	this->m_startTime = INT_MIN;
	this->m_extraData = NULL;
	this->m_extraLength = 0;
	this->m_duration = INT_MIN;
	this->m_loopCount = -1;

	this->SetType(e_action);
	this->m_location.Fill(FLT_MAX);
	this->m_direction.Fill(FLT_MAX);
	this->m_up.Fill(FLT_MAX);
	this->m_unk0x84 = NULL;
	this->m_unk0x88 = 0;
	this->m_origin = NULL;
	this->m_unk0x90 = INT_MIN;
}

// FUNCTION: LEGO1 0x100ad940
MxLong MxDSAction::GetDuration()
{
	return this->m_duration;
}

// FUNCTION: LEGO1 0x100ad950
void MxDSAction::SetDuration(MxLong p_duration)
{
	this->m_duration = p_duration;
}

// FUNCTION: LEGO1 0x100ad960
MxBool MxDSAction::HasId(MxU32 p_objectId)
{
	return this->GetObjectId() == p_objectId;
}

// FUNCTION: LEGO1 0x100ada40
void MxDSAction::SetUnknown90(MxLong p_unk0x90)
{
	this->m_unk0x90 = p_unk0x90;
}

// FUNCTION: LEGO1 0x100ada50
MxLong MxDSAction::GetUnknown90()
{
	return this->m_unk0x90;
}

// FUNCTION: LEGO1 0x100ada80
MxDSAction::~MxDSAction()
{
	delete[] this->m_extraData;
}

// FUNCTION: LEGO1 0x100adaf0
void MxDSAction::CopyFrom(MxDSAction& p_dsAction)
{
	this->SetObjectId(p_dsAction.GetObjectId());
	this->m_flags = p_dsAction.m_flags;
	this->m_startTime = p_dsAction.m_startTime;
	this->m_duration = p_dsAction.m_duration;
	this->m_loopCount = p_dsAction.m_loopCount;
	this->m_location = p_dsAction.m_location;
	this->m_direction = p_dsAction.m_direction;
	this->m_up = p_dsAction.m_up;
	AppendData(p_dsAction.m_extraLength, p_dsAction.m_extraData);
	this->m_unk0x84 = p_dsAction.m_unk0x84;
	this->m_unk0x88 = p_dsAction.m_unk0x88;
	this->m_origin = p_dsAction.m_origin;
	this->m_unk0x90 = p_dsAction.m_unk0x90;
}

// FUNCTION: LEGO1 0x100adbd0
undefined4 MxDSAction::VTable0x14()
{
	return MxDSObject::VTable0x14();
}

// FUNCTION: LEGO1 0x100adbe0
MxU32 MxDSAction::GetSizeOnDisk()
{
	MxU32 totalSizeOnDisk;

	totalSizeOnDisk = MxDSObject::GetSizeOnDisk() + 90 + this->m_extraLength;
	this->m_sizeOnDisk = totalSizeOnDisk - MxDSObject::GetSizeOnDisk();

	return totalSizeOnDisk;
}

// FUNCTION: LEGO1 0x100adc10
MxDSAction& MxDSAction::operator=(MxDSAction& p_dsAction)
{
	if (this == &p_dsAction) {
		return *this;
	}

	MxDSObject::operator=(p_dsAction);
	this->CopyFrom(p_dsAction);
	return *this;
}

// FUNCTION: LEGO1 0x100adc40
MxDSAction* MxDSAction::Clone()
{
	MxDSAction* clone = new MxDSAction();

	if (clone) {
		*clone = *this;
	}

	return clone;
}

// FUNCTION: LEGO1 0x100adcd0
MxLong MxDSAction::GetElapsedTime()
{
	return Timer()->GetTime() - this->m_unk0x90;
}

// FUNCTION: LEGO1 0x100add00
void MxDSAction::MergeFrom(MxDSAction& p_dsAction)
{
	if (p_dsAction.m_startTime != INT_MIN) {
		this->m_startTime = p_dsAction.m_startTime;
	}

	if (p_dsAction.GetDuration() != INT_MIN) {
		this->m_duration = p_dsAction.GetDuration();
	}

	if (p_dsAction.m_loopCount != -1) {
		this->m_loopCount = p_dsAction.m_loopCount;
	}

	if (p_dsAction.m_location[0] != FLT_MAX) {
		this->m_location[0] = p_dsAction.m_location[0];
	}
	if (p_dsAction.m_location[1] != FLT_MAX) {
		this->m_location[1] = p_dsAction.m_location[1];
	}
	if (p_dsAction.m_location[2] != FLT_MAX) {
		this->m_location[2] = p_dsAction.m_location[2];
	}

	if (p_dsAction.m_direction[0] != FLT_MAX) {
		this->m_direction[0] = p_dsAction.m_direction[0];
	}
	if (p_dsAction.m_direction[1] != FLT_MAX) {
		this->m_direction[1] = p_dsAction.m_direction[1];
	}
	if (p_dsAction.m_direction[2] != FLT_MAX) {
		this->m_direction[2] = p_dsAction.m_up[2]; // This is correct
	}

	if (p_dsAction.m_up[0] != FLT_MAX) {
		this->m_up[0] = p_dsAction.m_up[0];
	}
	if (p_dsAction.m_up[1] != FLT_MAX) {
		this->m_up[1] = p_dsAction.m_up[1];
	}
	if (p_dsAction.m_up[2] != FLT_MAX) {
		this->m_up[2] = p_dsAction.m_up[2];
	}

	MxU16 extraLength = p_dsAction.m_extraLength;
	char* extraData = p_dsAction.m_extraData;

	// Taking those references forces the compiler to move the values onto the stack.
	// The original code most likely looked different, but this yields a 100% match.
	MxU16& extraLengthRef = extraLength;
	char*& extraDataRef = extraData;
	if (extraLength && extraData) {
		if (!this->m_extraData || !strncmp("XXX", this->m_extraData, 3)) {
			delete[] this->m_extraData;
			this->m_extraLength = 0;
			AppendData(extraLength, extraData);
		}
	}
}

// FUNCTION: LEGO1 0x100ade60
void MxDSAction::AppendData(MxU16 p_extraLength, const char* p_extraData)
{
	if (this->m_extraData == p_extraData || !p_extraData) {
		return;
	}

	if (this->m_extraLength) {
		char* concat = new char[p_extraLength + this->m_extraLength + sizeof(g_sep)];
		memcpy(concat, this->m_extraData, this->m_extraLength);

		*(MxU16*) &concat[this->m_extraLength] = g_sep;
		memcpy(&concat[this->m_extraLength + sizeof(g_sep)], p_extraData, p_extraLength);

		this->m_extraLength += p_extraLength + sizeof(g_sep);
		delete[] this->m_extraData;
		this->m_extraData = concat;
	}
	else {
		char* copy = new char[p_extraLength];
		this->m_extraData = copy;

		if (copy) {
			this->m_extraLength = p_extraLength;
			memcpy(copy, p_extraData, p_extraLength);
		}
	}
}

// FUNCTION: LEGO1 0x100adf70
void MxDSAction::Deserialize(MxU8** p_source, MxS16 p_unk0x24)
{
	MxDSObject::Deserialize(p_source, p_unk0x24);

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
		AppendData(extraLength, (char*) *p_source);
		*p_source += extraLength;
	}
}
