#ifndef LEGOCACHESOUNDMANAGER_H
#define LEGOCACHESOUNDMANAGER_H

#include "decomp.h"
#include "legocachsound.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

// SIZE 0x08
struct LegoCacheSoundEntry {
	LegoCacheSoundEntry() : m_sound(NULL), m_name(NULL) {}
	LegoCacheSoundEntry(LegoCacheSound* p_sound, const char* p_name) : m_sound(p_sound), m_name(p_name) {}
	LegoCacheSoundEntry(LegoCacheSound* p_sound) : m_sound(p_sound), m_name(p_sound->GetString0x48().GetData()) {}

	// FUNCTION: LEGO1 0x1003d030
	~LegoCacheSoundEntry()
	{
		if (m_sound == NULL && m_name != NULL) {
			delete[] const_cast<char*>(m_name);
		}
	}

	bool operator==(LegoCacheSoundEntry) const { return 0; }
	bool operator<(LegoCacheSoundEntry) const { return 0; }

	inline LegoCacheSound* GetSound() const { return m_sound; }
	inline const char* GetName() const { return m_name; }

	friend struct Set100d6b4cComparator;

private:
	LegoCacheSound* m_sound; // 0x00
	const char* m_name;      // 0x04
};

struct Set100d6b4cComparator {
	bool operator()(const LegoCacheSoundEntry& p_a, const LegoCacheSoundEntry& p_b) const
	{
		return strcmpi(p_a.m_name, p_b.m_name) > 0;
	}
};

typedef set<LegoCacheSoundEntry, Set100d6b4cComparator> Set100d6b4c;
typedef list<LegoCacheSoundEntry> List100d6b4c;

// VTABLE: LEGO1 0x100d6b4c
// SIZE 0x20
class LegoCacheSoundManager {
public:
	LegoCacheSoundManager() {}
	~LegoCacheSoundManager();

	virtual MxResult Tickle(); // vtable+0x00

	LegoCacheSound* FUN_1003d170(const char* p_key);
	LegoCacheSound* FUN_1003d290(LegoCacheSound* p_sound);
	LegoCacheSound* FUN_1003dae0(const char* p_one, const char* p_two, MxBool p_three);
	LegoCacheSound* FUN_1003db10(LegoCacheSound* p_one, const char* p_two, MxBool p_three);
	void FUN_1003dc40(LegoCacheSound** p_und);

private:
	Set100d6b4c m_set;   // 0x04
	List100d6b4c m_list; // 0x14
};

// TODO: Function names subject to change.

// clang-format off
// TEMPLATE: LEGO1 0x10029c30
// _Tree<LegoCacheSoundEntry,LegoCacheSoundEntry,set<LegoCacheSoundEntry,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_Kfn,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::~_Tree<LegoCacheSoundEntry,LegoCacheSoundEntry,set<LegoCacheSoundEntry,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_Kfn,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >

// TEMPLATE: LEGO1 0x10029d10
// _Tree<LegoCacheSoundEntry,LegoCacheSoundEntry,set<LegoCacheSoundEntry,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_Kfn,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::iterator::_Inc

// TEMPLATE: LEGO1 0x10029d50
// _Tree<LegoCacheSoundEntry,LegoCacheSoundEntry,set<LegoCacheSoundEntry,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_Kfn,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::erase

// TEMPLATE: LEGO1 0x1002a1b0
// _Tree<LegoCacheSoundEntry,LegoCacheSoundEntry,set<LegoCacheSoundEntry,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_Kfn,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_Erase

// TEMPLATE: LEGO1 0x1002a210
// list<LegoCacheSoundEntry,allocator<LegoCacheSoundEntry> >::~list<LegoCacheSoundEntry,allocator<LegoCacheSoundEntry> >

// TEMPLATE: LEGO1 0x1002a2a0
// set<LegoCacheSoundEntry,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::~set<LegoCacheSoundEntry,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >

// TEMPLATE: LEGO1 0x1002a2f0
// Set<LegoCacheSoundEntry,Set100d6b4cComparator>::~Set<LegoCacheSoundEntry,Set100d6b4cComparator>

// TEMPLATE: LEGO1 0x1002a340
// List<LegoCacheSoundEntry>::~List<LegoCacheSoundEntry>

// TEMPLATE: LEGO1 0x1003dab0
// list<LegoCacheSoundEntry,allocator<LegoCacheSoundEntry> >::_Buynode

// TEMPLATE: LEGO1 0x1003d450
// _Tree<LegoCacheSoundEntry,LegoCacheSoundEntry,set<LegoCacheSoundEntry,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_Kfn,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::insert

// TEMPLATE: LEGO1 0x1003d6f0
// _Tree<LegoCacheSoundEntry,LegoCacheSoundEntry,set<LegoCacheSoundEntry,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_Kfn,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::iterator::_Dec

// TEMPLATE: LEGO1 0x1003d740
// _Tree<LegoCacheSoundEntry,LegoCacheSoundEntry,set<LegoCacheSoundEntry,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_Kfn,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_BuyNode

// TEMPLATE: LEGO1 0x1003d760
// _Tree<LegoCacheSoundEntry,LegoCacheSoundEntry,set<LegoCacheSoundEntry,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_Kfn,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_Insert

// TEMPLATE: LEGO1 0x1003d9f0
// _Tree<LegoCacheSoundEntry,LegoCacheSoundEntry,set<LegoCacheSoundEntry,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_Kfn,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_Lrotate

// TEMPLATE: LEGO1 0x1003da50
// _Tree<LegoCacheSoundEntry,LegoCacheSoundEntry,set<LegoCacheSoundEntry,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_Kfn,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_Rrotate

// GLOBAL: LEGO1 0x100f31cc
// _Tree<LegoCacheSoundEntry,LegoCacheSoundEntry,set<LegoCacheSoundEntry,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_Kfn,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_Nil
// clang-format on

#endif // LEGOCACHESOUNDMANAGER_H
