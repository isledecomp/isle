#include "mxticklethread.h"

#include "decomp.h"
#include "mxmisc.h"
#include "mxtimer.h"

DECOMP_SIZE_ASSERT(MxTickleThread, 0x20)

// FUNCTION: LEGO1 0x100b8bb0
MxTickleThread::MxTickleThread(MxCore* p_target, MxS32 p_frequencyMS)
{
	m_target = p_target;
	m_frequencyMS = p_frequencyMS;
}

// Match except for register allocation
// FUNCTION: LEGO1 0x100b8c90
MxResult MxTickleThread::Run()
{
	MxTimer* timer = Timer();
	MxS32 lastTickled = -m_frequencyMS;

	while (IsRunning()) {
		MxLong currentTime = timer->GetTime();

		if (currentTime < lastTickled) {
			lastTickled = -m_frequencyMS;
		}

		MxS32 timeRemainingMS = (m_frequencyMS - currentTime) + lastTickled;
		if (timeRemainingMS <= 0) {
			m_target->Tickle();
			timeRemainingMS = 0;
			lastTickled = currentTime;
		}

		Sleep(timeRemainingMS);
	}

	return MxThread::Run();
}
