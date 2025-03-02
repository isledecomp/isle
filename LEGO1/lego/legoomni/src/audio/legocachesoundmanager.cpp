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
		sound->Stop();
		delete sound;
	}

	while (!m_list.empty()) {
		sound = (*m_list.begin()).GetSound();
		// TODO: LegoCacheSoundEntry::~LegoCacheSoundEntry should not be inlined here
		m_list.erase(m_list.begin());
		sound->Stop();
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
		if (sound->GetUnknown0x58()) {
			sound->FUN_10006be0();
		}
	}

	List100d6b4c::iterator listIter = m_list.begin();
	while (listIter != m_list.end()) {
		LegoCacheSound* sound = (*listIter).GetSound();

		if (sound->GetUnknown0x58()) {
			sound->FUN_10006be0();
			listIter++;
		}
		else {
			sound->Stop();
			m_list.erase(listIter++);
			delete sound;
		}
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x1003d170
// FUNCTION: BETA10 0x1006539d
LegoCacheSound* LegoCacheSoundManager::FindSoundByKey(const char* p_key)
{
	// This function has changed completely since BETA10, but its calls suggest the match is correct

	char* key = new char[strlen(p_key) + 1];
	strcpy(key, p_key);

	Set100d6b4c::iterator it = m_set.find(LegoCacheSoundEntry(NULL, key));
	if (it != m_set.end()) {
		return (*it).GetSound();
	}

	return NULL;
}

// FUNCTION: LEGO1 0x1003d290
LegoCacheSound* LegoCacheSoundManager::ManageSoundEntry(LegoCacheSound* p_sound)
{
	Set100d6b4c::iterator it = m_set.find(LegoCacheSoundEntry(p_sound));
	if (it != m_set.end()) {
		LegoCacheSound* sound = (*it).GetSound();

		if (sound->GetUnknown0x58()) {
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
// FUNCTION: BETA10 0x10065502
LegoCacheSound* LegoCacheSoundManager::Play(const char* p_key, const char* p_name, MxBool p_looping)
{
	return Play(FindSoundByKey(p_key), p_name, p_looping);
}

// FUNCTION: LEGO1 0x1003db10
// FUNCTION: BETA10 0x10065537
LegoCacheSound* LegoCacheSoundManager::Play(LegoCacheSound* p_sound, const char* p_name, MxBool p_looping)
{
	if (!p_sound) {
		return NULL;
	}

	if (p_sound->GetUnknown0x58()) {
		LegoCacheSound* clone = p_sound->Clone();

		if (clone) {
			LegoCacheSound* sound = ManageSoundEntry(clone);
			sound->Play(p_name, p_looping);
			return sound;
		}
	}
	else {
		p_sound->Play(p_name, p_looping);
		return p_sound;
	}

	return NULL;
}

// FUNCTION: LEGO1 0x1003db80
// FUNCTION: BETA10 0x100656a7
void LegoCacheSoundManager::Stop(LegoCacheSound*& p_sound)
{
#ifdef COMPAT_MODE
	Set100d6b4c::iterator setIter;
	for (setIter = m_set.begin(); setIter != m_set.end(); setIter++) {
#else
	for (Set100d6b4c::iterator setIter = m_set.begin(); setIter != m_set.end(); setIter++) {
#endif
		if ((*setIter).GetSound() == p_sound) {
			p_sound->Stop();
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
		if (sound == p_sound) {
			p_sound->Stop();
			return;
		}
	}
}

// FUNCTION: LEGO1 0x1003dc40
void LegoCacheSoundManager::Destroy(LegoCacheSound*& p_sound)
{
#ifdef COMPAT_MODE
	Set100d6b4c::iterator setIter;
	for (setIter = m_set.begin(); setIter != m_set.end(); setIter++) {
#else
	for (Set100d6b4c::iterator setIter = m_set.begin(); setIter != m_set.end(); setIter++) {
#endif
		if ((*setIter).GetSound() == p_sound) {
			p_sound->Stop();

			delete p_sound;
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
		if (sound == p_sound) {
			p_sound->Stop();

			delete sound;
			m_list.erase(listIter);
			return;
		}
	}
}
