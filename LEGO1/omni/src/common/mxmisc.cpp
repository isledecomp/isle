#include "mxmisc.h"

#include "mxomni.h"

// FUNCTION: LEGO1 0x100acea0
MxObjectFactory* ObjectFactory()
{
	return MxOmni::GetInstance()->GetObjectFactory();
}

// FUNCTION: LEGO1 0x100aceb0
MxNotificationManager* NotificationManager()
{
	return MxOmni::GetInstance()->GetNotificationManager();
}

// FUNCTION: LEGO1 0x100acec0
MxTickleManager* TickleManager()
{
	return MxOmni::GetInstance()->GetTickleManager();
}

// FUNCTION: LEGO1 0x100aced0
MxTimer* Timer()
{
	return MxOmni::GetInstance()->GetTimer();
}

// FUNCTION: LEGO1 0x100acee0
MxAtomIdCounterSet* AtomIdCounterSet()
{
	return MxOmni::GetInstance()->GetAtomIdCounterSet();
}

// FUNCTION: LEGO1 0x100acef0
MxStreamer* Streamer()
{
	return MxOmni::GetInstance()->GetStreamer();
}

// FUNCTION: LEGO1 0x100acf00
MxSoundManager* MSoundManager()
{
	return MxOmni::GetInstance()->GetSoundManager();
}

// FUNCTION: LEGO1 0x100acf10
MxVideoManager* MVideoManager()
{
	return MxOmni::GetInstance()->GetVideoManager();
}

// FUNCTION: LEGO1 0x100acf20
MxVariableTable* VariableTable()
{
	return MxOmni::GetInstance()->GetVariableTable();
}

// FUNCTION: LEGO1 0x100acf30
MxMusicManager* MusicManager()
{
	return MxOmni::GetInstance()->GetMusicManager();
}

// FUNCTION: LEGO1 0x100acf40
MxEventManager* EventManager()
{
	return MxOmni::GetInstance()->GetEventManager();
}

// FUNCTION: LEGO1 0x100acf50
MxResult Start(MxDSAction* p_dsAction)
{
	return MxOmni::GetInstance()->Start(p_dsAction);
}

// FUNCTION: LEGO1 0x100acf70
void DeleteObject(MxDSAction& p_dsAction)
{
	MxOmni::GetInstance()->DeleteObject(p_dsAction);
}
