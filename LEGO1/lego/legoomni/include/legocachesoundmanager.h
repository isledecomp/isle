#ifndef LEGOCACHESOUNDMANAGER_H
#define LEGOCACHESOUNDMANAGER_H

#include "decomp.h"
#include "legocachsound.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

#pragma warning(disable : 4237)

// SIZE 0x08
struct LegoCacheSoundEntry {
	LegoCacheSoundEntry() : m_sound(NULL), m_name(NULL) {}
	LegoCacheSoundEntry(LegoCacheSound* p_sound, const char* p_name) : m_sound(p_sound), m_name(p_name) {}
	LegoCacheSoundEntry(LegoCacheSound* p_sound) : m_sound(p_sound), m_name(p_sound->GetUnknown0x48().GetData()) {}

	// FUNCTION: LEGO1 0x1003d030
	~LegoCacheSoundEntry()
	{
		if (m_sound == NULL && m_name != NULL) {
			delete[] const_cast<char*>(m_name);
		}
	}

	bool operator==(LegoCacheSoundEntry) const { return 0; }
	bool operator<(LegoCacheSoundEntry) const { return 0; }

	LegoCacheSound* GetSound() const { return m_sound; }
	const char* GetName() const { return m_name; }

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
// VTABLE: BETA10 0x101becac
// SIZE 0x20
class LegoCacheSoundManager {
public:
	// FUNCTION: BETA10 0x100d0a60
	LegoCacheSoundManager() {}

	~LegoCacheSoundManager();

	virtual MxResult Tickle(); // vtable+0x00

	LegoCacheSound* FindSoundByKey(const char* p_key);
	LegoCacheSound* ManageSoundEntry(LegoCacheSound* p_sound);
	LegoCacheSound* Play(const char* p_key, const char* p_name, MxBool p_looping);
	LegoCacheSound* Play(LegoCacheSound* p_sound, const char* p_name, MxBool p_looping);
	void Stop(LegoCacheSound*& p_sound);
	void Destroy(LegoCacheSound*& p_sound);

private:
	Set100d6b4c m_set;   // 0x04
	List100d6b4c m_list; // 0x14
};

// SYNTHETIC: BETA10 0x100d06b0
// LegoCacheSoundManager::`scalar deleting destructor'

// TODO: Function names subject to change.

// clang-format off
// TEMPLATE: LEGO1 0x10029c30 SYMBOL
// ??1?$_Tree@ULegoCacheSoundEntry@@U1@U_Kfn@?$set@ULegoCacheSoundEntry@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@QAE@XZ

// TEMPLATE: LEGO1 0x10029d10 SYMBOL
// ?_Inc@iterator@?$_Tree@ULegoCacheSoundEntry@@U1@U_Kfn@?$set@ULegoCacheSoundEntry@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@QAEXXZ

// TEMPLATE: LEGO1 0x10029d50 SYMBOL
// ?erase@?$_Tree@ULegoCacheSoundEntry@@U1@U_Kfn@?$set@ULegoCacheSoundEntry@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@QAE?AViterator@1@V21@@Z

// TEMPLATE: LEGO1 0x1002a1b0 SYMBOL
// ?_Erase@?$_Tree@ULegoCacheSoundEntry@@U1@U_Kfn@?$set@ULegoCacheSoundEntry@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@IAEXPAU_Node@1@@Z

// TEMPLATE: LEGO1 0x1002a210 SYMBOL
// ??1?$list@ULegoCacheSoundEntry@@V?$allocator@ULegoCacheSoundEntry@@@@@@QAE@XZ

// TEMPLATE: LEGO1 0x1002a2a0 SYMBOL
// ??1?$set@ULegoCacheSoundEntry@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@QAE@XZ

// TEMPLATE: LEGO1 0x1002a2f0
// Set<LegoCacheSoundEntry,Set100d6b4cComparator>::~Set<LegoCacheSoundEntry,Set100d6b4cComparator>

// TEMPLATE: LEGO1 0x1002a340
// List<LegoCacheSoundEntry>::~List<LegoCacheSoundEntry>

// TEMPLATE: LEGO1 0x1003dab0 SYMBOL
// ?_Buynode@?$list@ULegoCacheSoundEntry@@V?$allocator@ULegoCacheSoundEntry@@@@@@IAEPAU_Node@1@PAU21@0@Z

// TEMPLATE: LEGO1 0x1003d450 SYMBOL
// ?insert@?$_Tree@ULegoCacheSoundEntry@@U1@U_Kfn@?$set@ULegoCacheSoundEntry@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@QAE?AU?$pair@Viterator@?$_Tree@ULegoCacheSoundEntry@@U

// TEMPLATE: LEGO1 0x1003d6f0 SYMBOL
// ?_Dec@iterator@?$_Tree@ULegoCacheSoundEntry@@U1@U_Kfn@?$set@ULegoCacheSoundEntry@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@QAEXXZ

// TEMPLATE: LEGO1 0x1003d740 SYMBOL
// ?_Buynode@?$_Tree@ULegoCacheSoundEntry@@U1@U_Kfn@?$set@ULegoCacheSoundEntry@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@IAEPAU_Node@1@PAU21@W4_Redbl@1@@Z

// TEMPLATE: LEGO1 0x1003d760 SYMBOL
// ?_Insert@?$_Tree@ULegoCacheSoundEntry@@U1@U_Kfn@?$set@ULegoCacheSoundEntry@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@IAE?AViterator@1@PAU_Node@1@0ABULegoCacheSoundEntry@@

// TEMPLATE: LEGO1 0x1003d9f0 SYMBOL
// ?_Lrotate@?$_Tree@ULegoCacheSoundEntry@@U1@U_Kfn@?$set@ULegoCacheSoundEntry@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@IAEXPAU_Node@1@@Z

// TEMPLATE: LEGO1 0x1003da50 SYMBOL
// ?_Rrotate@?$_Tree@ULegoCacheSoundEntry@@U1@U_Kfn@?$set@ULegoCacheSoundEntry@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@USet100d6b4cComparator@@V?$allocator@ULegoCacheSoundEntry@@@@@@IAEXPAU_Node@1@@Z

// GLOBAL: LEGO1 0x100f31cc
// _Tree<LegoCacheSoundEntry,LegoCacheSoundEntry,set<LegoCacheSoundEntry,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_Kfn,Set100d6b4cComparator,allocator<LegoCacheSoundEntry> >::_Nil
// clang-format on

#endif // LEGOCACHESOUNDMANAGER_H
