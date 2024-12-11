#include "act3cop.h"

#include "act3.h"
#include "act3brickster.h"
#include "legocachesoundmanager.h"
#include "legosoundmanager.h"
#include "misc.h"
#include "roi/legoroi.h"

#include <assert.h>

DECOMP_SIZE_ASSERT(Act3Cop, 0x188)

// STUB: LEGO1 0x1003fe30
Act3Cop::Act3Cop()
{
	// TODO
}

// FUNCTION: LEGO1 0x1003ff70
// FUNCTION: BETA10 0x10018526
MxResult Act3Cop::VTable0x94(LegoPathActor* p_actor, MxBool p_bool)
{
	LegoROI* roi = p_actor->GetROI();
	if (p_bool && !strncmp(roi->GetName(), "dammo", 5)) {
		MxS32 count = -1;
		if (sscanf(roi->GetName(), "dammo%d", &count) != 1) {
			assert(0);
		}

		assert(m_world);
		((Act3*) m_world)->EatDonut(count);
		m_unk0x20 = m_lastTime + 2000;
		SetWorldSpeed(6.0);

		assert(SoundManager()->GetCacheSoundManager());
		SoundManager()->GetCacheSoundManager()->Play("eatdn", NULL, FALSE);
		FUN_10040360();
	}
	else {
		if (((Act3*) m_world)->GetBrickster()->GetROI() != roi) {
			if (p_bool) {
				return Act3Actor::VTable0x94(p_actor, p_bool);
			}
		}
		else {
			((Act3*) m_world)->GoodEnding(roi->GetLocal2World());
		}
	}

	return SUCCESS;
}

// STUB: LEGO1 0x10040060
void Act3Cop::ParseAction(char* p_extra)
{
	// TODO
}

// STUB: LEGO1 0x100401f0
void Act3Cop::VTable0x70(float p_time)
{
	// TODO
}

// STUB: LEGO1 0x10040360
// STUB: BETA10 0x10018c6a
void Act3Cop::FUN_10040360()
{
	// TODO
}

// STUB: LEGO1 0x10040d20
MxResult Act3Cop::VTable0x9c()
{
	// TODO
	return SUCCESS;
}
