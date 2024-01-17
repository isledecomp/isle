#include "mxdsparallelaction.h"

#include "mxdsmediaaction.h"

DECOMP_SIZE_ASSERT(MxDSParallelAction, 0x9c)

// FUNCTION: LEGO1 0x100cae80
MxDSParallelAction::MxDSParallelAction()
{
	this->SetType(e_parallelAction);
}

// FUNCTION: LEGO1 0x100cb040
MxDSParallelAction::~MxDSParallelAction()
{
}

// FUNCTION: LEGO1 0x100cb090
void MxDSParallelAction::CopyFrom(MxDSParallelAction& p_dsParallelAction)
{
}

// FUNCTION: LEGO1 0x100cb0a0
MxDSParallelAction& MxDSParallelAction::operator=(MxDSParallelAction& p_dsParallelAction)
{
	if (this == &p_dsParallelAction)
		return *this;

	MxDSMultiAction::operator=(p_dsParallelAction);
	this->CopyFrom(p_dsParallelAction);
	return *this;
}

// FUNCTION: LEGO1 0x100cb0d0
MxDSAction* MxDSParallelAction::Clone()
{
	MxDSParallelAction* clone = new MxDSParallelAction();

	if (clone)
		*clone = *this;

	return clone;
}

// FUNCTION: LEGO1 0x100cb160
MxLong MxDSParallelAction::GetDuration()
{
	if (this->m_duration)
		return this->m_duration;

	MxDSActionListCursor cursor(this->m_actions);
	MxDSAction* action;

	while (cursor.Next(action)) {
		if (!action)
			continue;

		MxLong duration = action->GetDuration();
		if (duration == -1) {
			this->m_duration = -1;
			break;
		}

		duration += action->GetStartTime();
		if (action->IsA("MxDSMediaAction")) {
			MxLong sustainTime = ((MxDSMediaAction*) action)->GetSustainTime();

			if (sustainTime == -1)
				duration = -1;
			else if (sustainTime)
				duration += sustainTime;
		}

		if (duration == -1) {
			this->m_duration = -1;
			break;
		}

		if (this->m_duration < duration)
			this->m_duration = duration;
	}

	if (this->IsBit3())
		this->m_duration *= this->m_loopCount;

	return this->m_duration;
}
