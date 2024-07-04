#include "bumpbouy.h"

#include "isle.h"
#include "islepathactor.h"
#include "legogamestate.h"
#include "legovideomanager.h"
#include "misc.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxnotificationparam.h"
#include "mxtransitionmanager.h"
#include "scripts.h"

#include <assert.h>

DECOMP_SIZE_ASSERT(BumpBouy, 0x174)

// FUNCTION: LEGO1 0x10027220
BumpBouy::BumpBouy()
{
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x10027360
BumpBouy::~BumpBouy()
{
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x10027400
// FUNCTION: BETA10 0x100262d9
MxLong BumpBouy::Notify(MxParam& p_param)
{
	MxLong result = 0;
	IslePathActor* user = (IslePathActor*) UserActor();
	assert(user);

	if (user->IsA("Jetski") && ((MxNotificationParam&) p_param).GetNotification() == c_notificationClick) {
		VideoManager()->SetRender3D(FALSE);
		user->SetWorldSpeed(0);
		user->Exit();

		Act1State* isleState = (Act1State*) GameState()->GetState("Act1State");
		assert(isleState);
		isleState->m_unk0x018 = 5;

		Isle* isle = (Isle*) FindWorld(*g_isleScript, 0);
		assert(isle);
		isle->SetDestLocation(LegoGameState::e_jetrace);

		TransitionManager()->StartTransition(MxTransitionManager::e_mosaic, 50, FALSE, FALSE);
		result = 1;
	}

	return result;
}
