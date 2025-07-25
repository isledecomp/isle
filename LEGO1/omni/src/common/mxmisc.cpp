#include "mxmisc.h"

#include "mxmain.h"

#include <assert.h>

// FUNCTION: LEGO1 0x100acea0
// FUNCTION: BETA10 0x10124d30
MxObjectFactory* ObjectFactory()
{
	assert(MxOmni::GetInstance());
	return MxOmni::GetInstance()->GetObjectFactory();
}

// FUNCTION: LEGO1 0x100aceb0
// FUNCTION: BETA10 0x10124d77
MxNotificationManager* NotificationManager()
{
	assert(MxOmni::GetInstance());
	return MxOmni::GetInstance()->GetNotificationManager();
}

// FUNCTION: LEGO1 0x100acec0
// FUNCTION: BETA10 0x10124dbe
MxTickleManager* TickleManager()
{
	assert(MxOmni::GetInstance());
	return MxOmni::GetInstance()->GetTickleManager();
}

// FUNCTION: LEGO1 0x100aced0
// FUNCTION: BETA10 0x10124e05
MxTimer* Timer()
{
	assert(MxOmni::GetInstance());
	return MxOmni::GetInstance()->GetTimer();
}

// FUNCTION: LEGO1 0x100acee0
// FUNCTION: BETA10 0x10124e4c
MxAtomSet* AtomSet()
{
	assert(MxOmni::GetInstance());
	return MxOmni::GetInstance()->GetAtomSet();
}

// FUNCTION: LEGO1 0x100acef0
// FUNCTION: BETA10 0x10124e93
MxStreamer* Streamer()
{
	assert(MxOmni::GetInstance());
	return MxOmni::GetInstance()->GetStreamer();
}

// FUNCTION: LEGO1 0x100acf00
// FUNCTION: BETA10 0x10124eda
MxSoundManager* MSoundManager()
{
	assert(MxOmni::GetInstance());
	return MxOmni::GetInstance()->GetSoundManager();
}

// FUNCTION: LEGO1 0x100acf10
// FUNCTION: BETA10 0x10124f21
MxVideoManager* MVideoManager()
{
	assert(MxOmni::GetInstance());
	return MxOmni::GetInstance()->GetVideoManager();
}

// FUNCTION: LEGO1 0x100acf20
// FUNCTION: BETA10 0x10124f68
MxVariableTable* VariableTable()
{
	assert(MxOmni::GetInstance());
	return MxOmni::GetInstance()->GetVariableTable();
}

// FUNCTION: LEGO1 0x100acf30
// FUNCTION: BETA10 0x10124faf
MxMusicManager* MusicManager()
{
	assert(MxOmni::GetInstance());
	return MxOmni::GetInstance()->GetMusicManager();
}

// FUNCTION: LEGO1 0x100acf40
// FUNCTION: BETA10 0x10124ff6
MxEventManager* EventManager()
{
	assert(MxOmni::GetInstance());
	return MxOmni::GetInstance()->GetEventManager();
}

// FUNCTION: LEGO1 0x100acf50
// FUNCTION: BETA10 0x1012503d
MxResult Start(MxDSAction* p_dsAction)
{
	assert(MxOmni::GetInstance());
	return MxOmni::GetInstance()->Start(p_dsAction);
}

// FUNCTION: LEGO1 0x100acf70
// FUNCTION: BETA10 0x10125098
void DeleteObject(MxDSAction& p_dsAction)
{
	assert(MxOmni::GetInstance());
	MxOmni::GetInstance()->DeleteObject(p_dsAction);
}
