#include "mxdsserialaction.h"

#include "mxdebug.h"
#include "mxdsmediaaction.h"

DECOMP_SIZE_ASSERT(MxDSSerialAction, 0xa8)

// FUNCTION: LEGO1 0x100ca9d0
// FUNCTION: BETA10 0x10159cf3
MxDSSerialAction::MxDSSerialAction()
{
	m_type = e_serialAction;
	m_cursor = new MxDSActionListCursor(m_actionList);
	m_unk0xa0 = 0;
}

// FUNCTION: LEGO1 0x100caac0
// FUNCTION: BETA10 0x1015b280
void MxDSSerialAction::SetDuration(MxLong p_duration)
{
	m_duration = p_duration;
}

// FUNCTION: LEGO1 0x100cac10
// FUNCTION: BETA10 0x10159dd1
MxDSSerialAction::~MxDSSerialAction()
{
	delete m_cursor;
	m_cursor = NULL;
}

// FUNCTION: LEGO1 0x100cac90
// FUNCTION: BETA10 0x10159e73
void MxDSSerialAction::CopyFrom(MxDSSerialAction& p_dsSerialAction)
{
	if (p_dsSerialAction.m_cursor->HasMatch() || p_dsSerialAction.m_unk0xa0) {
		MxTrace("copying a serialAction while someone is traversing it's list\n");
	}
}

// FUNCTION: BETA10 0x10159ec2
MxDSSerialAction::MxDSSerialAction(MxDSSerialAction& p_dsSerialAction) : MxDSMultiAction(p_dsSerialAction)
{
	CopyFrom(p_dsSerialAction);
}

// FUNCTION: LEGO1 0x100caca0
// FUNCTION: BETA10 0x10159f43
MxDSSerialAction& MxDSSerialAction::operator=(MxDSSerialAction& p_dsSerialAction)
{
	if (this == &p_dsSerialAction) {
		return *this;
	}

	MxDSMultiAction::operator=(p_dsSerialAction);
	CopyFrom(p_dsSerialAction);
	return *this;
}

// FUNCTION: LEGO1 0x100cacd0
// FUNCTION: BETA10 0x10159f8a
MxDSAction* MxDSSerialAction::Clone()
{
	MxDSSerialAction* clone = new MxDSSerialAction();

	if (clone) {
		*clone = *this;
	}

	return clone;
}

// FUNCTION: LEGO1 0x100cad60
// FUNCTION: BETA10 0x1015a034
MxLong MxDSSerialAction::GetDuration()
{
	if (m_duration) {
		return m_duration;
	}

	MxDSActionListCursor cursor(m_actionList);
	MxDSAction* action;

	while (cursor.Next(action)) {
		if (action) {
			m_duration += action->GetDuration() + action->GetStartTime();

			if (action->IsA("MxDSMediaAction")) {
				MxLong sustainTime = ((MxDSMediaAction*) action)->GetSustainTime();

				if (sustainTime && sustainTime != -1) {
					m_duration += sustainTime;
				}
			}
		}
	}

	return m_duration;
}
