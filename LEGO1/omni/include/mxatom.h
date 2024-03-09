#ifndef MXATOM_H
#define MXATOM_H

#include "mxstl/stlcompat.h"
#include "mxstring.h"
#include "mxtypes.h"

// Counts the number of existing MxAtomId objects based
// on the matching char* string. A <map> seems fit for purpose here:
// We have an MxString as a key and MxU16 as the value.
// And yet a <set> is the best match. The malloc in MxOmni::Create
// for the _Nil node asks for more bytes than a regular node if a <map>
// is used, but all nodes are 20 bytes wide with a <set>.
// Also: the increment/decrement methods suggest a custom type was used
// for the combined key_value_pair, which doesn't seem possible with <map>.

// SIZE 0x14
class MxAtomIdCounter {
public:
	// always inlined
	MxAtomIdCounter(const char* p_str)
	{
		m_key = p_str;
		m_value = 0;
	}

	void Inc();
	void Dec();
	inline MxString* GetKey() { return &m_key; }
	inline MxU16 GetValue() { return m_value; }

private:
	MxString m_key;
	MxU16 m_value;
};

struct MxAtomIdCounterCompare {
	// FUNCTION: LEGO1 0x100ad120
	int operator()(MxAtomIdCounter* const& p_val0, MxAtomIdCounter* const& p_val1) const
	{
		return strcmp(p_val0->GetKey()->GetData(), p_val1->GetKey()->GetData()) > 0;
	}
};

class MxAtomIdCounterSet : public set<MxAtomIdCounter*, MxAtomIdCounterCompare> {};

enum LookupMode {
	e_exact = 0,
	e_lowerCase,
	e_upperCase,
	e_lowerCase2,
};

// SIZE 0x04
class MxAtomId {
public:
	MxAtomId(const char*, LookupMode);
	MxAtomId& operator=(const MxAtomId& p_atomId);
	~MxAtomId();

	MxAtomId() { this->m_internal = 0; }

	inline MxBool operator==(const MxAtomId& p_atomId) const { return this->m_internal == p_atomId.m_internal; }
	inline MxBool operator!=(const MxAtomId& p_atomId) const { return this->m_internal != p_atomId.m_internal; }

	void Clear();

	const char* GetInternal() const { return m_internal; }

private:
	MxAtomIdCounter* GetCounter(const char*, LookupMode);
	void Destroy();

	const char* m_internal; // 0x00
};

// SYNTHETIC: LEGO1 0x100ad170
// MxAtomIdCounter::~MxAtomIdCounter

// clang-format off
// TEMPLATE: LEGO1 0x100ad480
// _Tree<MxAtomIdCounter *,MxAtomIdCounter *,set<MxAtomIdCounter *,MxAtomIdCounterCompare,allocator<MxAtomIdCounter *> >::_Kfn,MxAtomIdCounterCompare,allocator<MxAtomIdCounter *> >::iterator::_Dec
// clang-format on

// clang-format off
// TEMPLATE: LEGO1 0x100ad780
// _Tree<MxAtomIdCounter *,MxAtomIdCounter *,set<MxAtomIdCounter *,MxAtomIdCounterCompare,allocator<MxAtomIdCounter *> >::_Kfn,MxAtomIdCounterCompare,allocator<MxAtomIdCounter *> >::_Lbound
// clang-format on

// clang-format off
// TEMPLATE: LEGO1 0x100ad4d0
// _Tree<MxAtomIdCounter *,MxAtomIdCounter *,set<MxAtomIdCounter *,MxAtomIdCounterCompare,allocator<MxAtomIdCounter *> >::_Kfn,MxAtomIdCounterCompare,allocator<MxAtomIdCounter *> >::_Insert
// clang-format on

// clang-format off
// TEMPLATE: LEGO1 0x100af6d0
// _Tree<MxAtomIdCounter *,MxAtomIdCounter *,set<MxAtomIdCounter *,MxAtomIdCounterCompare,allocator<MxAtomIdCounter *> >::_Kfn,MxAtomIdCounterCompare,allocator<MxAtomIdCounter *> >::~_Tree<MxAtomIdCounter *,MxAtomIdCounter *,set<MxAtomIdCounter *,MxAtomIdCou
// clang-format on

// clang-format off
// TEMPLATE: LEGO1 0x100af7a0
// _Tree<MxAtomIdCounter *,MxAtomIdCounter *,set<MxAtomIdCounter *,MxAtomIdCounterCompare,allocator<MxAtomIdCounter *> >::_Kfn,MxAtomIdCounterCompare,allocator<MxAtomIdCounter *> >::iterator::_Inc
// clang-format on

// clang-format off
// TEMPLATE: LEGO1 0x100af7e0
// _Tree<MxAtomIdCounter *,MxAtomIdCounter *,set<MxAtomIdCounter *,MxAtomIdCounterCompare,allocator<MxAtomIdCounter *> >::_Kfn,MxAtomIdCounterCompare,allocator<MxAtomIdCounter *> >::erase
// clang-format on

// clang-format off
// TEMPLATE: LEGO1 0x100afc40
// _Tree<MxAtomIdCounter *,MxAtomIdCounter *,set<MxAtomIdCounter *,MxAtomIdCounterCompare,allocator<MxAtomIdCounter *> >::_Kfn,MxAtomIdCounterCompare,allocator<MxAtomIdCounter *> >::_Erase
// clang-format on

// clang-format off
// TEMPLATE: LEGO1 0x100afc80
// set<MxAtomIdCounter *,MxAtomIdCounterCompare,allocator<MxAtomIdCounter *> >::~set<MxAtomIdCounter *,MxAtomIdCounterCompare,allocator<MxAtomIdCounter *> >
// clang-format on

// TEMPLATE: LEGO1 0x100afe40
// Set<MxAtomIdCounter *,MxAtomIdCounterCompare>::~Set<MxAtomIdCounter *,MxAtomIdCounterCompare>

#endif // MXATOM_H
