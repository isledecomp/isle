#include "mxdsparallelaction.h"

#include "mxdsmediaaction.h"

DECOMP_SIZE_ASSERT(MxDSParallelAction, 0x9c)

// FUNCTION: LEGO1 0x100cae80
// FUNCTION: BETA10 0x1015a14d
MxDSParallelAction::MxDSParallelAction()
{
	m_type = e_parallelAction;
}

// FUNCTION: LEGO1 0x100cb040
// FUNCTION: BETA10 0x1015a1c5
MxDSParallelAction::~MxDSParallelAction()
{
}

// FUNCTION: LEGO1 0x100cb090
// FUNCTION: BETA10 0x1015a22d
void MxDSParallelAction::CopyFrom(MxDSParallelAction& p_dsParallelAction)
{
}

// FUNCTION: BETA10 0x1015a245
MxDSParallelAction::MxDSParallelAction(MxDSParallelAction& p_dsParallelAction) : MxDSMultiAction(p_dsParallelAction)
{
	CopyFrom(p_dsParallelAction);
}

// FUNCTION: LEGO1 0x100cb0a0
// FUNCTION: BETA10 0x1015a2c6
MxDSParallelAction& MxDSParallelAction::operator=(MxDSParallelAction& p_dsParallelAction)
{
	if (this == &p_dsParallelAction) {
		return *this;
	}

	MxDSMultiAction::operator=(p_dsParallelAction);
	CopyFrom(p_dsParallelAction);
	return *this;
}

// FUNCTION: LEGO1 0x100cb0d0
// FUNCTION: BETA10 0x1015a30d
MxDSAction* MxDSParallelAction::Clone()
{
	MxDSParallelAction* clone = new MxDSParallelAction();

	if (clone) {
		*clone = *this;
	}

	return clone;
}

// FUNCTION: LEGO1 0x100cb160
// FUNCTION: BETA10 0x1015a3b7
MxLong MxDSParallelAction::GetDuration()
{
	if (m_duration) {
		return m_duration;
	}

	MxDSActionListCursor cursor(m_actionList);
	MxDSAction* action;

	while (cursor.Next(action)) {
		if (!action) {
			continue;
		}

		MxLong duration = action->GetDuration();
		if (duration == -1) {
			m_duration = -1;
			break;
		}

		duration += action->GetStartTime();
		if (action->IsA("MxDSMediaAction")) {
			MxLong sustainTime = ((MxDSMediaAction*) action)->GetSustainTime();

			if (sustainTime == -1) {
				duration = -1;
			}
			else if (sustainTime) {
				duration += sustainTime;
			}
		}

		if (duration == -1) {
			m_duration = -1;
			break;
		}

		if (m_duration < duration) {
			m_duration = duration;
		}
	}

	if (IsBit3()) {
		m_duration *= m_loopCount;
	}

	return m_duration;
}
