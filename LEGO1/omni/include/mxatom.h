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
class MxAtom {
public:
	// always inlined
	// FUNCTION: BETA10 0x10123720
	MxAtom(const char* p_str)
	{
		m_key = p_str;
		m_value = 0;
	}

	void Inc();
	void Dec();

	// FUNCTION: BETA10 0x101236d0
	MxString& GetKey() { return m_key; }

	// SYNTHETIC: BETA10 0x10124a50
	// MxAtom::`scalar deleting destructor'

private:
	MxString m_key; // 0x00
	MxU16 m_value;  // 0x10
};

struct MxAtomCompare {
	// FUNCTION: LEGO1 0x100ad120
	// FUNCTION: BETA10 0x10123980
	int operator()(MxAtom* const& p_val0, MxAtom* const& p_val1) const
	{
		return strcmp(p_val0->GetKey().GetData(), p_val1->GetKey().GetData()) > 0;
	}
};

class MxAtomSet : public set<MxAtom*, MxAtomCompare> {};

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
	~MxAtomId();

	MxAtomId& operator=(const MxAtomId& p_atomId);

	// FUNCTION: BETA10 0x100178d0
	MxBool operator==(const MxAtomId& p_atomId) const { return this->m_internal == p_atomId.m_internal; }

#ifdef COMPAT_MODE
	// Required for modern compilers.
	// MSVC 4.20 uses a synthetic function from INCLUDE/UTILITY that inverts operator==
	MxBool operator!=(const MxAtomId& p_atomId) const { return this->m_internal != p_atomId.m_internal; }
#endif

	// FUNCTION: BETA10 0x10025d40
	MxAtomId() { this->m_internal = 0; }

	void Clear();

	// FUNCTION: BETA10 0x100735e0
	const char* GetInternal() const { return m_internal; }

private:
	// FUNCTION: BETA10 0x101236f0
	MxAtomId& operator=(const MxString& p_key)
	{
		m_internal = p_key.GetData();
		return *this;
	}

	MxAtom* GetAtom(const char*, LookupMode);
	void Destroy();

	const char* m_internal; // 0x00
};

// SYNTHETIC: BETA10 0x1002b520
// ??9@YAHABVMxAtomId@@0@Z
// aka MxAtomId::operator!=

// SYNTHETIC: LEGO1 0x100ad170
// MxAtom::~MxAtom

// clang-format off
// TEMPLATE: LEGO1 0x100ad480
// _Tree<MxAtom *,MxAtom *,set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::_Kfn,MxAtomCompare,allocator<MxAtom *> >::iterator::_Dec
// clang-format on

// clang-format off
// TEMPLATE: LEGO1 0x100ad780
// _Tree<MxAtom *,MxAtom *,set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::_Kfn,MxAtomCompare,allocator<MxAtom *> >::_Lbound
// clang-format on

// clang-format off
// TEMPLATE: LEGO1 0x100ad4d0
// _Tree<MxAtom *,MxAtom *,set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::_Kfn,MxAtomCompare,allocator<MxAtom *> >::_Insert
// clang-format on

// clang-format off
// TEMPLATE: BETA10 0x101237a0
// _Tree<MxAtom *,MxAtom *,set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::_Kfn,MxAtomCompare,allocator<MxAtom *> >::const_iterator::operator*
// clang-format on

// clang-format off
// TEMPLATE: LEGO1 0x100af6d0
// TEMPLATE: BETA10 0x10131170
// _Tree<MxAtom *,MxAtom *,set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::_Kfn,MxAtomCompare,allocator<MxAtom *> >::~_Tree<MxAtom *,MxAtom *,set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::_Kfn,MxAtomCompare,allocator<MxAtom *> >
// clang-format on

// clang-format off
// TEMPLATE: LEGO1 0x100af7a0
// _Tree<MxAtom *,MxAtom *,set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::_Kfn,MxAtomCompare,allocator<MxAtom *> >::iterator::_Inc
// clang-format on

// clang-format off
// TEMPLATE: LEGO1 0x100af7e0
// TEMPLATE: BETA10 0x10131210
// _Tree<MxAtom *,MxAtom *,set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::_Kfn,MxAtomCompare,allocator<MxAtom *> >::erase
// clang-format on

// TEMPLATE: BETA10 0x10131460
// _Tree<MxAtom *,MxAtom *,set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::_Kfn,MxAtomCompare,allocator<MxAtom *>
// >::size

// clang-format off
// TEMPLATE: LEGO1 0x100afc40
// _Tree<MxAtom *,MxAtom *,set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::_Kfn,MxAtomCompare,allocator<MxAtom *> >::_Erase
// clang-format on

// clang-format off
// TEMPLATE: LEGO1 0x100afc80
// TEMPLATE: BETA10 0x10132080
// set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::~set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >
// clang-format on

// TEMPLATE: LEGO1 0x100afe40
// TEMPLATE: BETA10 0x101320e0
// Set<MxAtom *,MxAtomCompare>::~Set<MxAtom *,MxAtomCompare>

// TEMPLATE: BETA10 0x10132140
// set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::begin

// clang-format off
// GLOBAL: LEGO1 0x101013f0
// GLOBAL: BETA10 0x10201264
// _Tree<MxAtom *,MxAtom *,set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::_Kfn,MxAtomCompare,allocator<MxAtom *> >::_Nil
// clang-format on

// TEMPLATE: BETA10 0x10132170
// _Tree<MxAtom *,MxAtom *,set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::_Kfn,MxAtomCompare,allocator<MxAtom *>
// >::begin

// TEMPLATE: BETA10 0x101321d0
// set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::size

// TEMPLATE: BETA10 0x101321f0
// set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::erase

// TEMPLATE: BETA10 0x101237f0
// set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::end

// TEMPLATE: BETA10 0x101238b0
// set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::find

// clang-format off
// TEMPLATE: BETA10 0x101238e0
// _Tree<MxAtom *,MxAtom *,set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::_Kfn,MxAtomCompare,allocator<MxAtom *> >::find
// clang-format on

// SYNTHETIC: BETA10 0x10123bf0
// MxAtom::~MxAtom

// TEMPLATE: BETA10 0x10123c50
// set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::insert

// SYNTHETIC: BETA10 0x10130fc0
// MxAtomSet::MxAtomSet

// TEMPLATE: BETA10 0x10131030
// Set<MxAtom *,MxAtomCompare>::Set<MxAtom *,MxAtomCompare>

// clang-format off
// TEMPLATE: BETA10 0x101310a0
// set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >

// TEMPLATE: BETA10 0x10131120
// _Tree<MxAtom *,MxAtom *,set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::_Kfn,MxAtomCompare,allocator<MxAtom *> >::_Tree<MxAtom *,MxAtom *,set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::_Kfn,MxAtomCompare,allocator<MxAtom *> >

// TEMPLATE: BETA10 0x10131f30
// _Tree<MxAtom *,MxAtom *,set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::_Kfn,MxAtomCompare,allocator<MxAtom *> >::_Init
// clang-format on

// SYNTHETIC: BETA10 0x101322a0
// MxAtomSet::`scalar deleting destructor'

// SYNTHETIC: BETA10 0x101322e0
// MxAtomSet::~MxAtomSet

#endif // MXATOM_H
