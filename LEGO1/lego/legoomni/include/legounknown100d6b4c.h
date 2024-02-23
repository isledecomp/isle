#ifndef LEGOUNKNOWN100D6B4C_H
#define LEGOUNKNOWN100D6B4C_H

#include "decomp.h"
#include "legocachesound.h"
#include "mxstl/stlcompat.h"
#include "mxtypes.h"

// SIZE 0x08
struct Element100d6b4c {
	Element100d6b4c() : m_sound(NULL), m_name(NULL) {}
	Element100d6b4c(LegoCacheSound* p_sound, const char* p_name) : m_sound(p_sound), m_name(p_name) {}
	Element100d6b4c(LegoCacheSound* p_sound) : m_sound(p_sound), m_name(p_sound->GetString0x48().GetData()) {}

	// FUNCTION: LEGO1 0x1003d030
	~Element100d6b4c()
	{
		if (m_sound == NULL && m_name != NULL) {
			delete[] const_cast<char*>(m_name);
		}
	}

	bool operator==(Element100d6b4c) const { return 0; }
	bool operator<(Element100d6b4c) const { return 0; }

	inline LegoCacheSound* GetSound() const { return m_sound; }
	inline const char* GetName() const { return m_name; }

	friend struct Set100d6b4cComparator;

private:
	LegoCacheSound* m_sound; // 0x00
	const char* m_name;      // 0x04
};

struct Set100d6b4cComparator {
	bool operator()(const Element100d6b4c& p_a, const Element100d6b4c& p_b) const
	{
		return strcmpi(p_a.m_name, p_b.m_name) > 0;
	}
};

typedef set<Element100d6b4c, Set100d6b4cComparator> Set100d6b4c;
typedef list<Element100d6b4c> List100d6b4c;

// VTABLE: LEGO1 0x100d6b4c
// SIZE 0x20
class LegoUnknown100d6b4c {
public:
	LegoUnknown100d6b4c() {}
	~LegoUnknown100d6b4c();

	virtual MxResult Tickle(); // vtable+0x00

	LegoCacheSound* FUN_1003d170(const char* p_key);
	LegoCacheSound* FUN_1003d290(LegoCacheSound* p_sound);
	void FUN_1003dae0(char* p_one, char* p_two, MxBool p_three);
	LegoCacheSound* FUN_1003db10(LegoCacheSound* p_one, char* p_two, MxBool p_three);
	void FUN_1003dc40(LegoCacheSound** p_und);

private:
	Set100d6b4c m_set;   // 0x04
	List100d6b4c m_list; // 0x14
};

// TODO: Function names subject to change.

// clang-format off
// TEMPLATE: LEGO1 0x10029c30
// _Tree<Element100d6b4c,Element100d6b4c,set<Element100d6b4c,Set100d6b4cComparator,allocator<Element100d6b4c> >::_Kfn,Set100d6b4cComparator,allocator<Element100d6b4c> >::~_Tree<Element100d6b4c,Element100d6b4c,set<Element100d6b4c,Set100d6b4cComparator,allocator<Element100d6b4c> >::_Kfn,Set100d6b4cComparator,allocator<Element100d6b4c> >

// TEMPLATE: LEGO1 0x10029d10
// _Tree<Element100d6b4c,Element100d6b4c,set<Element100d6b4c,Set100d6b4cComparator,allocator<Element100d6b4c> >::_Kfn,Set100d6b4cComparator,allocator<Element100d6b4c> >::iterator::_Inc

// TEMPLATE: LEGO1 0x10029d50
// _Tree<Element100d6b4c,Element100d6b4c,set<Element100d6b4c,Set100d6b4cComparator,allocator<Element100d6b4c> >::_Kfn,Set100d6b4cComparator,allocator<Element100d6b4c> >::erase

// TEMPLATE: LEGO1 0x1002a1b0
// _Tree<Element100d6b4c,Element100d6b4c,set<Element100d6b4c,Set100d6b4cComparator,allocator<Element100d6b4c> >::_Kfn,Set100d6b4cComparator,allocator<Element100d6b4c> >::_Erase

// TEMPLATE: LEGO1 0x1002a210
// list<Element100d6b4c,allocator<Element100d6b4c> >::~list<Element100d6b4c,allocator<Element100d6b4c> >

// TEMPLATE: LEGO1 0x1002a2a0
// set<Element100d6b4c,Set100d6b4cComparator,allocator<Element100d6b4c> >::~set<Element100d6b4c,Set100d6b4cComparator,allocator<Element100d6b4c> >

// TEMPLATE: LEGO1 0x1002a2f0
// Set<Element100d6b4c,Set100d6b4cComparator>::~Set<Element100d6b4c,Set100d6b4cComparator>

// TEMPLATE: LEGO1 0x1002a340
// List<Element100d6b4c>::~List<Element100d6b4c>

// TEMPLATE: LEGO1 0x1003dab0
// list<Element100d6b4c,allocator<Element100d6b4c> >::_Buynode

// TEMPLATE: LEGO1 0x1003d450
// _Tree<Element100d6b4c,Element100d6b4c,set<Element100d6b4c,Set100d6b4cComparator,allocator<Element100d6b4c> >::_Kfn,Set100d6b4cComparator,allocator<Element100d6b4c> >::insert

// TEMPLATE: LEGO1 0x1003d6f0
// _Tree<Element100d6b4c,Element100d6b4c,set<Element100d6b4c,Set100d6b4cComparator,allocator<Element100d6b4c> >::_Kfn,Set100d6b4cComparator,allocator<Element100d6b4c> >::iterator::_Dec

// TEMPLATE: LEGO1 0x1003d740
// _Tree<Element100d6b4c,Element100d6b4c,set<Element100d6b4c,Set100d6b4cComparator,allocator<Element100d6b4c> >::_Kfn,Set100d6b4cComparator,allocator<Element100d6b4c> >::_BuyNode

// TEMPLATE: LEGO1 0x1003d760
// _Tree<Element100d6b4c,Element100d6b4c,set<Element100d6b4c,Set100d6b4cComparator,allocator<Element100d6b4c> >::_Kfn,Set100d6b4cComparator,allocator<Element100d6b4c> >::_Insert

// TEMPLATE: LEGO1 0x1003d9f0
// _Tree<Element100d6b4c,Element100d6b4c,set<Element100d6b4c,Set100d6b4cComparator,allocator<Element100d6b4c> >::_Kfn,Set100d6b4cComparator,allocator<Element100d6b4c> >::_Lrotate

// TEMPLATE: LEGO1 0x1003da50
// _Tree<Element100d6b4c,Element100d6b4c,set<Element100d6b4c,Set100d6b4cComparator,allocator<Element100d6b4c> >::_Kfn,Set100d6b4cComparator,allocator<Element100d6b4c> >::_Rrotate

// GLOBAL: LEGO1 0x100f31cc
// _Tree<Element100d6b4c,Element100d6b4c,set<Element100d6b4c,Set100d6b4cComparator,allocator<Element100d6b4c> >::_Kfn,Set100d6b4cComparator,allocator<Element100d6b4c> >::_Nil
// clang-format on

#endif // LEGOUNKNOWN100D6B4C_H
