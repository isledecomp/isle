#include "legocachesoundmanager.h"

#include "legoworld.h"
#include "misc.h"

DECOMP_SIZE_ASSERT(LegoCacheSoundEntry, 0x08)
DECOMP_SIZE_ASSERT(LegoCacheSoundManager, 0x20)

// FUNCTION: LEGO1 0x1003cf20
LegoCacheSoundManager::~LegoCacheSoundManager()
{
	LegoCacheSound* sound;

	while (!m_set.empty()) {
		sound = (*m_set.begin()).GetSound();
		m_set.erase(m_set.begin());
		sound->FUN_10006b80();
		delete sound;
	}

	while (!m_list.empty()) {
		sound = (*m_list.begin()).GetSound();
		m_list.erase(m_list.begin());
		sound->FUN_10006b80();
		// DECOMP: delete should not be inlined here
		delete sound;
	}
}

// FUNCTION: LEGO1 0x1003d050
MxResult LegoCacheSoundManager::Tickle()
{
#ifdef COMPAT_MODE
	Set100d6b4c::iterator setIter;
	for (setIter = m_set.begin(); setIter != m_set.end(); setIter++) {
#else
	for (Set100d6b4c::iterator setIter = m_set.begin(); setIter != m_set.end(); setIter++) {
#endif
		LegoCacheSound* sound = (*setIter).GetSound();
		if (sound->GetUnk0x58()) {
			sound->FUN_10006be0();
		}
	}

	List100d6b4c::iterator listIter = m_list.begin();
	while (listIter != m_list.end()) {
		LegoCacheSound* sound = (*listIter).GetSound();

		if (sound->GetUnk0x58()) {
			sound->FUN_10006be0();
			listIter++;
		}
		else {
			sound->FUN_10006b80();
			m_list.erase(listIter++);
			delete sound;
		}
	}

	return SUCCESS;
}

// STUB: LEGO1 0x1003d170
LegoCacheSound* LegoCacheSoundManager::FUN_1003d170(const char* p_key)
{
	// TODO
	char* x = new char[strlen(p_key) + 1];
	strcpy(x, p_key);

	Set100d6b4c::iterator setIter;
	for (setIter = m_set.begin(); setIter != m_set.end(); setIter++) {
		if (!strcmpi((*setIter).GetName(), x)) {
			return (*setIter).GetSound();
		}
	}

	return NULL;
}

// FUNCTION: LEGO1 0x1003d290
LegoCacheSound* LegoCacheSoundManager::FUN_1003d290(LegoCacheSound* p_sound)
{
	Set100d6b4c::iterator it = m_set.find(LegoCacheSoundEntry(p_sound));
	if (it != m_set.end()) {
		LegoCacheSound* sound = (*it).GetSound();

		if (sound->GetUnk0x58()) {
			m_list.push_back(LegoCacheSoundEntry(p_sound));
			return p_sound;
		}
		else {
			delete p_sound;
			return sound;
		}
	}

	m_set.insert(LegoCacheSoundEntry(p_sound));
	LegoWorld* world = CurrentWorld();
	if (world) {
		world->Add(p_sound);
	}

	return p_sound;
}

// FUNCTION: LEGO1 0x1003dae0
LegoCacheSound* LegoCacheSoundManager::FUN_1003dae0(const char* p_one, const char* p_two, MxBool p_three)
{
	// DECOMP: Second parameter is LegoRoi::m_name (0xe4)
	return FUN_1003db10(FUN_1003d170(p_one), p_two, p_three);
}

// FUNCTION: LEGO1 0x1003db10
LegoCacheSound* LegoCacheSoundManager::FUN_1003db10(LegoCacheSound* p_one, const char* p_two, MxBool p_three)
{
	if (!p_one) {
		return NULL;
	}

	if (p_one->GetUnk0x58()) {
		LegoCacheSound* result = p_one->FUN_10006960();

		if (result) {
			LegoCacheSound* t = FUN_1003d290(result);
			t->FUN_10006a30(p_two, p_three);
			return t;
		}
	}
	else {
		p_one->FUN_10006a30(p_two, p_three);
		return p_one;
	}

	return NULL;
}

// FUNCTION: LEGO1 0x1003dc40
void LegoCacheSoundManager::FUN_1003dc40(LegoCacheSound** p_und)
{
	// Called during LegoWorld::Destroy like this:
	// SoundManager()->GetCacheSoundManager()->FUN_1003dc40(&sound);
	// LegoCacheSound*& p_sound?

#ifdef COMPAT_MODE
	Set100d6b4c::iterator setIter;
	for (setIter = m_set.begin(); setIter != m_set.end(); setIter++) {
#else
	for (Set100d6b4c::iterator setIter = m_set.begin(); setIter != m_set.end(); setIter++) {
#endif
		if ((*setIter).GetSound() == *p_und) {
			(*p_und)->FUN_10006b80();

			delete *p_und;
			m_set.erase(setIter);
			return;
		}
	}

#ifdef COMPAT_MODE
	List100d6b4c::iterator listIter;
	for (listIter = m_list.begin();; listIter++) {
#else
	for (List100d6b4c::iterator listIter = m_list.begin();; listIter++) {
#endif
		if (listIter == m_list.end()) {
			return;
		}

		LegoCacheSound* sound = (*listIter).GetSound();
		if (sound == *p_und) {
			(*p_und)->FUN_10006b80();

			delete sound;
			m_list.erase(listIter);
			return;
		}
	}
}
