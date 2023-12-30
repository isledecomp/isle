#ifndef MXATOMIDCOUNTER_H
#define MXATOMIDCOUNTER_H

#include "mxstl/stlcompat.h"
#include "mxstring.h"

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
	inline MxString* GetKey() { return &m_key; };
	inline MxU16 GetValue() { return m_value; };

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

#endif // MXATOMIDCOUNTER_H
