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
	m_type = e_action;
	m_flags = MxDSAction::c_enabled;
	m_extraLength = 0;
	m_extraData = NULL;
	m_startTime = INT_MIN;
	m_duration = INT_MIN;
	m_loopCount = -1;
	m_location.Fill(FLT_MAX);
	m_direction.Fill(FLT_MAX);
	m_up.Fill(FLT_MAX);
	m_notificationObject = NULL;
	m_unk0x88 = 0;
	m_origin = NULL;
	m_timeStarted = INT_MIN;
}

// FUNCTION: LEGO1 0x100ad940
// FUNCTION: BETA10 0x1012bc50
MxLong MxDSAction::GetDuration()
{
	return m_duration;
}

// FUNCTION: LEGO1 0x100ad950
// FUNCTION: BETA10 0x1012bc90
void MxDSAction::SetDuration(MxLong p_duration)
{
	m_duration = p_duration;
}

// FUNCTION: LEGO1 0x100ad960
// FUNCTION: BETA10 0x1012bcc0
MxBool MxDSAction::HasId(MxU32 p_objectId)
{
	return m_objectId == p_objectId;
}

// FUNCTION: LEGO1 0x100ada40
// FUNCTION: BETA10 0x1012bdf0
void MxDSAction::SetTimeStarted(MxLong p_timeStarted)
{
	m_timeStarted = p_timeStarted;
}

// FUNCTION: LEGO1 0x100ada50
// FUNCTION: BETA10 0x1012be20
MxLong MxDSAction::GetTimeStarted()
{
	return m_timeStarted;
}

// FUNCTION: LEGO1 0x100ada80
// FUNCTION: BETA10 0x1012b144
MxDSAction::~MxDSAction()
{
	delete[] m_extraData;
}

// FUNCTION: LEGO1 0x100adaf0
// FUNCTION: BETA10 0x1012b1c7
void MxDSAction::CopyFrom(MxDSAction& p_dsAction)
{
	m_objectId = p_dsAction.m_objectId;
	m_flags = p_dsAction.m_flags;
	m_startTime = p_dsAction.m_startTime;
	m_duration = p_dsAction.m_duration;
	m_loopCount = p_dsAction.m_loopCount;
	m_location = p_dsAction.m_location;
	m_direction = p_dsAction.m_direction;
	m_up = p_dsAction.m_up;
	AppendExtra(p_dsAction.m_extraLength, p_dsAction.m_extraData);
	m_notificationObject = p_dsAction.m_notificationObject;
	m_unk0x88 = p_dsAction.m_unk0x88;
	m_origin = p_dsAction.m_origin;
	m_timeStarted = p_dsAction.m_timeStarted;
}

// FUNCTION: BETA10 0x1012b2b3
MxDSAction::MxDSAction(MxDSAction& p_dsAction) : MxDSObject(p_dsAction)
{
	CopyFrom(p_dsAction);
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
	size += sizeof(MxU32);
	size += sizeof(MxS32);
	size += sizeof(MxS32);
	size += sizeof(MxS32);
	size += sizeof(double) * 3; // m_location
	size += sizeof(double) * 3; // m_direction
	size += sizeof(double) * 3; // m_up
	size += sizeof(MxU16);
	size += m_extraLength;

	m_sizeOnDisk = size - MxDSObject::GetSizeOnDisk();

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
	CopyFrom(p_dsAction);
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
	return Timer()->GetTime() - m_timeStarted;
}

// FUNCTION: LEGO1 0x100add00
// FUNCTION: BETA10 0x1012b4f5
void MxDSAction::MergeFrom(MxDSAction& p_dsAction)
{
	if (p_dsAction.GetStartTime() != INT_MIN) {
		m_startTime = p_dsAction.GetStartTime();
	}

	if (p_dsAction.GetDuration() != INT_MIN) {
		m_duration = p_dsAction.GetDuration();
	}

	if (p_dsAction.GetLoopCount() != -1) {
		m_loopCount = p_dsAction.GetLoopCount();
	}

	if (p_dsAction.GetLocation()[0] != FLT_MAX) {
		m_location[0] = p_dsAction.GetLocation()[0];
	}
	if (p_dsAction.GetLocation()[1] != FLT_MAX) {
		m_location[1] = p_dsAction.GetLocation()[1];
	}
	if (p_dsAction.GetLocation()[2] != FLT_MAX) {
		m_location[2] = p_dsAction.GetLocation()[2];
	}

	if (p_dsAction.GetDirection()[0] != FLT_MAX) {
		m_direction[0] = p_dsAction.GetDirection()[0];
	}
	if (p_dsAction.GetDirection()[1] != FLT_MAX) {
		m_direction[1] = p_dsAction.GetDirection()[1];
	}
	if (p_dsAction.GetDirection()[2] != FLT_MAX) {
		m_direction[2] = p_dsAction.GetUp()[2]; // This is correct
	}

	if (p_dsAction.GetUp()[0] != FLT_MAX) {
		m_up[0] = p_dsAction.GetUp()[0];
	}
	if (p_dsAction.GetUp()[1] != FLT_MAX) {
		m_up[1] = p_dsAction.GetUp()[1];
	}
	if (p_dsAction.GetUp()[2] != FLT_MAX) {
		m_up[2] = p_dsAction.GetUp()[2];
	}

	MxU16 extraLength;
	char* extraData;
	p_dsAction.GetExtra(extraLength, extraData);

	if (extraLength && extraData) {
		if (!m_extraData || !strncmp("XXX", m_extraData, 3)) {
			delete[] m_extraData;
			m_extraLength = 0;
			AppendExtra(extraLength, extraData);
		}
	}
}

// FUNCTION: LEGO1 0x100ade60
// FUNCTION: BETA10 0x1012b8a9
void MxDSAction::AppendExtra(MxU16 p_extraLength, const char* p_extraData)
{
	if (m_extraData == p_extraData) {
		return;
	}

	if (p_extraData) {
		if (m_extraLength) {
			char* newExtra = new char[p_extraLength + m_extraLength + sizeof(g_sep)];
			assert(newExtra);
			memcpy(newExtra, m_extraData, m_extraLength);
			memcpy(&newExtra[m_extraLength], &g_sep, sizeof(g_sep));
			memcpy(&newExtra[m_extraLength + sizeof(g_sep)], p_extraData, p_extraLength);

			m_extraLength += p_extraLength + sizeof(g_sep);
			delete[] m_extraData;
			m_extraData = newExtra;
		}
		else {
			m_extraData = new char[p_extraLength];

			if (m_extraData) {
				m_extraLength = p_extraLength;
				memcpy(m_extraData, p_extraData, p_extraLength);
			}
			else {
				assert(0);
			}
		}
	}
}

// FUNCTION: LEGO1 0x100adf70
// FUNCTION: BETA10 0x1012ba6a
void MxDSAction::Deserialize(MxU8*& p_source, MxS16 p_flags)
{
	MxDSObject::Deserialize(p_source, p_flags);

	// clang-format off
	m_flags           = *( MxU32*) p_source;  p_source += sizeof(MxU32);
	m_startTime       = *(MxLong*) p_source;  p_source += sizeof(MxS32);
	m_duration        = *(MxLong*) p_source;  p_source += sizeof(MxS32);
	m_loopCount       = *( MxS32*) p_source;  p_source += sizeof(MxS32);
	m_location[0]     = *(double*) p_source;  p_source += sizeof(double);
	m_location[1]     = *(double*) p_source;  p_source += sizeof(double);
	m_location[2]     = *(double*) p_source;  p_source += sizeof(double);
	m_direction[0]    = *(double*) p_source;  p_source += sizeof(double);
	m_direction[1]    = *(double*) p_source;  p_source += sizeof(double);
	m_direction[2]    = *(double*) p_source;  p_source += sizeof(double);
	m_up[0]           = *(double*) p_source;  p_source += sizeof(double);
	m_up[1]           = *(double*) p_source;  p_source += sizeof(double);
	m_up[2]           = *(double*) p_source;  p_source += sizeof(double);

	MxU16 extraLength = *( MxU16*) p_source;  p_source += sizeof(extraLength);
	// clang-format on

	if (extraLength) {
		AppendExtra(extraLength, (char*) p_source);
		p_source += extraLength;
	}
}
