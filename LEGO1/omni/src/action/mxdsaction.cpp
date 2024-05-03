#include "mxdsaction.h"

#include "mxmisc.h"
#include "mxtimer.h"
#include "mxutilities.h"

#include <assert.h>
#include <float.h>
#include <limits.h>

DECOMP_SIZE_ASSERT(MxDSAction, 0x94)

// GLOBAL: LEGO1 0x10101410
// GLOBAL: BETA10 0x10201f5c
MxU16 g_sep = TWOCC(',', ' ');

// FUNCTION: LEGO1 0x100ad810
// FUNCTION: BETA10 0x1012afd0
MxDSAction::MxDSAction()
{
	this->m_type = e_action;
	this->m_flags = MxDSAction::c_enabled;
	this->m_extraLength = 0;
	this->m_extraData = NULL;
	this->m_startTime = INT_MIN;
	this->m_duration = INT_MIN;
	this->m_loopCount = -1;

	// TODO: No convenience function used in the beta, but maybe a macro?
	{
		float max = FLT_MAX;
		float* v = &max;
		this->m_location.EqualsScalar(v);
	}

	{
		float max = FLT_MAX;
		float* v = &max;
		this->m_direction.EqualsScalar(v);
	}

	{
		float max = FLT_MAX;
		float* v = &max;
		this->m_up.EqualsScalar(v);
	}

	this->m_unk0x84 = NULL;
	this->m_unk0x88 = 0;
	this->m_origin = NULL;
	this->m_unk0x90 = INT_MIN;
}

// FUNCTION: LEGO1 0x100ad940
// FUNCTION: BETA10 0x1012bc50
MxLong MxDSAction::GetDuration()
{
	return this->m_duration;
}

// FUNCTION: LEGO1 0x100ad950
// FUNCTION: BETA10 0x1012bc90
void MxDSAction::SetDuration(MxLong p_duration)
{
	this->m_duration = p_duration;
}

// FUNCTION: LEGO1 0x100ad960
// FUNCTION: BETA10 0x1012bcc0
MxBool MxDSAction::HasId(MxU32 p_objectId)
{
	return this->m_objectId == p_objectId;
}

// FUNCTION: LEGO1 0x100ada40
// FUNCTION: BETA10 0x1012bdf0
void MxDSAction::SetUnknown90(MxLong p_unk0x90)
{
	this->m_unk0x90 = p_unk0x90;
}

// FUNCTION: LEGO1 0x100ada50
// FUNCTION: BETA10 0x1012be20
MxLong MxDSAction::GetUnknown90()
{
	return this->m_unk0x90;
}

// FUNCTION: LEGO1 0x100ada80
// FUNCTION: BETA10 0x1012b144
MxDSAction::~MxDSAction()
{
	delete[] this->m_extraData;
}

// FUNCTION: LEGO1 0x100adaf0
// FUNCTION: BETA10 0x1012b1c7
void MxDSAction::CopyFrom(MxDSAction& p_dsAction)
{
	this->m_objectId = p_dsAction.m_objectId;
	this->m_flags = p_dsAction.m_flags;
	this->m_startTime = p_dsAction.m_startTime;
	this->m_duration = p_dsAction.m_duration;
	this->m_loopCount = p_dsAction.m_loopCount;
	this->m_location = p_dsAction.m_location;
	this->m_direction = p_dsAction.m_direction;
	this->m_up = p_dsAction.m_up;
	AppendExtra(p_dsAction.m_extraLength, p_dsAction.m_extraData);
	this->m_unk0x84 = p_dsAction.m_unk0x84;
	this->m_unk0x88 = p_dsAction.m_unk0x88;
	this->m_origin = p_dsAction.m_origin;
	this->m_unk0x90 = p_dsAction.m_unk0x90;
}

// FUNCTION: BETA10 0x1012b2b3
MxDSAction::MxDSAction(MxDSAction& p_dsAction) : MxDSObject(p_dsAction)
{
	this->CopyFrom(p_dsAction);
}

// FUNCTION: LEGO1 0x100adbd0
// FUNCTION: BETA10 0x1012b355
undefined4 MxDSAction::VTable0x14()
{
	return MxDSObject::VTable0x14();
}

// FUNCTION: LEGO1 0x100adbe0
// FUNCTION: BETA10 0x1012b373
MxU32 MxDSAction::GetSizeOnDisk()
{
	MxU32 size = MxDSObject::GetSizeOnDisk();
	size += sizeof(m_flags);
	size += sizeof(m_startTime);
	size += sizeof(m_duration);
	size += sizeof(m_loopCount);
	size += sizeof(double) * 3; // m_location
	size += sizeof(double) * 3; // m_direction
	size += sizeof(double) * 3; // m_up
	size += sizeof(m_extraLength);
	size += this->m_extraLength;

	this->m_sizeOnDisk = size - MxDSObject::GetSizeOnDisk();

	return size;
}

// FUNCTION: LEGO1 0x100adc10
// FUNCTION: BETA10 0x1012b3d9
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
// FUNCTION: BETA10 0x1012b420
MxDSAction* MxDSAction::Clone()
{
	MxDSAction* clone = new MxDSAction();

	if (clone) {
		*clone = *this;
	}

	return clone;
}

// FUNCTION: LEGO1 0x100adcd0
// FUNCTION: BETA10 0x1012b4ca
MxLong MxDSAction::GetElapsedTime()
{
	return Timer()->GetTime() - this->m_unk0x90;
}

// FUNCTION: LEGO1 0x100add00
// FUNCTION: BETA10 0x1012b4f5
void MxDSAction::MergeFrom(MxDSAction& p_dsAction)
{
	if (p_dsAction.GetStartTime() != INT_MIN) {
		this->m_startTime = p_dsAction.GetStartTime();
	}

	if (p_dsAction.GetDuration() != INT_MIN) {
		this->m_duration = p_dsAction.GetDuration();
	}

	if (p_dsAction.GetLoopCount() != -1) {
		this->m_loopCount = p_dsAction.GetLoopCount();
	}

	if (p_dsAction.GetLocation()[0] != FLT_MAX) {
		this->m_location[0] = p_dsAction.GetLocation()[0];
	}
	if (p_dsAction.GetLocation()[1] != FLT_MAX) {
		this->m_location[1] = p_dsAction.GetLocation()[1];
	}
	if (p_dsAction.GetLocation()[2] != FLT_MAX) {
		this->m_location[2] = p_dsAction.GetLocation()[2];
	}

	if (p_dsAction.GetDirection()[0] != FLT_MAX) {
		this->m_direction[0] = p_dsAction.GetDirection()[0];
	}
	if (p_dsAction.GetDirection()[1] != FLT_MAX) {
		this->m_direction[1] = p_dsAction.GetDirection()[1];
	}
	if (p_dsAction.GetDirection()[2] != FLT_MAX) {
		this->m_direction[2] = p_dsAction.GetUp()[2]; // This is correct
	}

	if (p_dsAction.GetUp()[0] != FLT_MAX) {
		this->m_up[0] = p_dsAction.GetUp()[0];
	}
	if (p_dsAction.GetUp()[1] != FLT_MAX) {
		this->m_up[1] = p_dsAction.GetUp()[1];
	}
	if (p_dsAction.GetUp()[2] != FLT_MAX) {
		this->m_up[2] = p_dsAction.GetUp()[2];
	}

	MxU16 extraLength;
	char* extraData;
	p_dsAction.GetExtra(extraLength, extraData);

	if (extraLength && extraData) {
		if (!this->m_extraData || !strncmp("XXX", this->m_extraData, 3)) {
			delete[] this->m_extraData;
			this->m_extraLength = 0;
			AppendExtra(extraLength, extraData);
		}
	}
}

// FUNCTION: LEGO1 0x100ade60
// FUNCTION: BETA10 0x1012b8a9
void MxDSAction::AppendExtra(MxU16 p_extraLength, const char* p_extraData)
{
	if (this->m_extraData == p_extraData) {
		return;
	}

	if (p_extraData) {
		if (this->m_extraLength) {
			char* newExtra = new char[p_extraLength + this->m_extraLength + sizeof(g_sep)];
			assert(newExtra);
			memcpy(newExtra, this->m_extraData, this->m_extraLength);
			memcpy(&newExtra[this->m_extraLength], &g_sep, sizeof(g_sep));
			memcpy(&newExtra[this->m_extraLength + sizeof(g_sep)], p_extraData, p_extraLength);

			this->m_extraLength += p_extraLength + sizeof(g_sep);
			delete[] this->m_extraData;
			this->m_extraData = newExtra;
		}
		else {
			this->m_extraData = new char[p_extraLength];

			if (this->m_extraData) {
				this->m_extraLength = p_extraLength;
				memcpy(this->m_extraData, p_extraData, p_extraLength);
			}
			else {
				assert(0);
			}
		}
	}
}

// FUNCTION: LEGO1 0x100adf70
// FUNCTION: BETA10 0x1012ba6a
void MxDSAction::Deserialize(MxU8*& p_source, MxS16 p_unk0x24)
{
	MxDSObject::Deserialize(p_source, p_unk0x24);

	// clang-format off
	this->m_flags        = *( MxU32*) p_source;  p_source += 4;
	this->m_startTime    = *(MxLong*) p_source;  p_source += 4;
	this->m_duration     = *(MxLong*) p_source;  p_source += 4;
	this->m_loopCount    = *( MxS32*) p_source;  p_source += 4;
	this->m_location[0]  = *(double*) p_source;  p_source += 8;
	this->m_location[1]  = *(double*) p_source;  p_source += 8;
	this->m_location[2]  = *(double*) p_source;  p_source += 8;
	this->m_direction[0] = *(double*) p_source;  p_source += 8;
	this->m_direction[1] = *(double*) p_source;  p_source += 8;
	this->m_direction[2] = *(double*) p_source;  p_source += 8;
	this->m_up[0]        = *(double*) p_source;  p_source += 8;
	this->m_up[1]        = *(double*) p_source;  p_source += 8;
	this->m_up[2]        = *(double*) p_source;  p_source += 8;

	MxU16 extraLength    = *( MxU16*) p_source;  p_source += 2;
	// clang-format on

	if (extraLength) {
		AppendExtra(extraLength, (char*) p_source);
		p_source += extraLength;
	}
}
