#include "mxdsserialaction.h"

#include "mxdsmediaaction.h"

DECOMP_SIZE_ASSERT(MxDSSerialAction, 0xa8)

// OFFSET: LEGO1 0x100ca9d0
MxDSSerialAction::MxDSSerialAction()
{
	this->SetType(MxDSType_SerialAction);
	this->m_cursor = new MxDSActionListCursor(this->m_actions);
	this->m_unk0xa0 = 0;
}

// OFFSET: LEGO1 0x100caac0
void MxDSSerialAction::SetDuration(MxLong p_duration)
{
	this->m_duration = p_duration;
}

// OFFSET: LEGO1 0x100cac10
MxDSSerialAction::~MxDSSerialAction()
{
	if (this->m_cursor)
		delete this->m_cursor;

	this->m_cursor = NULL;
}

// OFFSET: LEGO1 0x100cac90
void MxDSSerialAction::CopyFrom(MxDSSerialAction& p_dsSerialAction)
{
}

// OFFSET: LEGO1 0x100caca0
MxDSSerialAction& MxDSSerialAction::operator=(MxDSSerialAction& p_dsSerialAction)
{
	if (this == &p_dsSerialAction)
		return *this;

	MxDSMultiAction::operator=(p_dsSerialAction);
	this->CopyFrom(p_dsSerialAction);
	return *this;
}

// OFFSET: LEGO1 0x100cacd0
MxDSAction* MxDSSerialAction::Clone()
{
	MxDSSerialAction* clone = new MxDSSerialAction();

	if (clone)
		*clone = *this;

	return clone;
}

// OFFSET: LEGO1 0x100cad60
MxLong MxDSSerialAction::GetDuration()
{
	if (this->m_duration)
		return this->m_duration;

	MxDSActionListCursor cursor(this->m_actions);
	MxDSAction* action;

	while (cursor.Next(action)) {
		if (!action)
			continue;

		this->m_duration += action->GetDuration() + action->GetStartTime();

		if (action->IsA("MxDSMediaAction")) {
			MxLong sustainTime = ((MxDSMediaAction*) action)->GetSustainTime();

			if (sustainTime && sustainTime != -1)
				this->m_duration += sustainTime;
		}
	}

	return this->m_duration;
}