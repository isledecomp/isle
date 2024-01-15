#ifndef MXATOMID_H
#define MXATOMID_H

#include "mxatomidcounter.h"
#include "mxtypes.h"

enum LookupMode {
	LookupMode_Exact = 0,
	LookupMode_LowerCase = 1,
	LookupMode_UpperCase = 2,
	LookupMode_LowerCase2 = 3
};

// SIZE 0x04
class MxAtomId {
public:
	__declspec(dllexport) MxAtomId(const char*, LookupMode);
	__declspec(dllexport) MxAtomId& operator=(const MxAtomId& p_atomId);
	__declspec(dllexport) ~MxAtomId();

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

#endif // MXATOMID_H
