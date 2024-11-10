#include "act2genactor.h"

#include "legocachesoundmanager.h"
#include "legosoundmanager.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxtimer.h"
#include "roi/legoroi.h"

DECOMP_SIZE_ASSERT(Act2GenActor, 0x154)

// GLOBAL: LEGO1 0x100f0f18
MxLong Act2GenActor::g_lastHitActorTime = 0;

// FUNCTION: LEGO1 0x10018740
// FUNCTION: BETA10 0x1000c7a0
MxResult Act2GenActor::VTable0x94(LegoPathActor* p_actor, MxBool)
{
	MxLong time = Timer()->GetTime();
	MxLong diff = time - g_lastHitActorTime;

	if (strcmp(p_actor->GetROI()->GetName(), "pepper")) {
		return SUCCESS;
	}

	g_lastHitActorTime = time;
	if (diff > 1000) {
		SoundManager()->GetCacheSoundManager()->Play("hitactor", NULL, FALSE);
	}

	return SUCCESS;
}
