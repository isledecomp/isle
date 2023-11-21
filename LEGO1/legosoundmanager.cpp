#include "legosoundmanager.h"

#include "mxautolocker.h"

// OFFSET: LEGO1 0x100298a0
LegoSoundManager::LegoSoundManager()
{
	Init();
}

// OFFSET: LEGO1 0x10029940
LegoSoundManager::~LegoSoundManager()
{
	Destroy(TRUE);
}

// OFFSET: LEGO1 0x100299a0
void LegoSoundManager::Init()
{
	unk0x40 = 0;
	unk0x3c = 0;
}

// OFFSET: LEGO1 0x100299b0 STUB
void LegoSoundManager::Destroy(MxBool p_fromDestructor)
{
}

// OFFSET: LEGO1 0x100299f0 STUB
MxResult LegoSoundManager::Create(MxU32 p_frequencyMS, MxBool p_createThread)
{
	return FAILURE;
}

// OFFSET: LEGO1 0x1002a390
void LegoSoundManager::Destroy()
{
	Destroy(FALSE);
}

// OFFSET: LEGO1 0x1002a3a0 STUB
MxResult LegoSoundManager::Tickle()
{
	MxMediaManager::Tickle();
	MxAutoLocker lock(&this->m_criticalSection);

	return 0; // TODO: call something in unk0x40
}
