#ifndef MXVARIABLETABLE_H
#define MXVARIABLETABLE_H

#include "mxhashtable.h"
#include "mxtypes.h"
#include "mxvariable.h"

// VTABLEADDR 0x100dc1c8
// SIZE 0x28
class MxVariableTable : public MxHashTable<MxVariable> {
public:
	MxVariableTable() { m_customDestructor = Destroy; }
	__declspec(dllexport) void SetVariable(const char* key, const char* value);
	__declspec(dllexport) void SetVariable(MxVariable* var);
	__declspec(dllexport) const char* GetVariable(const char* key);

	// OFFSET: LEGO1 0x100afdb0
	static void Destroy(MxVariable* p_obj) { p_obj->Destroy(); }

	virtual MxS8 Compare(MxVariable*, MxVariable*); // +0x14
	virtual MxU32 Hash(MxVariable*);                // +0x18
};

// OFFSET: LEGO1 0x100b0bd0 TEMPLATE
// MxHashTable<MxVariable>::~MxHashTable<MxVariable>

// OFFSET: LEGO1 0x100b7ab0 TEMPLATE
// MxHashTable<MxVariable>::Resize

// OFFSET: LEGO1 0x100b7b80 TEMPLATE
// MxHashTable<MxVariable>::_NodeInsert

#endif // MXVARIABLETABLE_H
