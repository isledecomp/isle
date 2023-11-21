#ifndef MXVARIABLETABLE_H
#define MXVARIABLETABLE_H

#include "mxhashtable.h"
#include "mxtypes.h"
#include "mxvariable.h"

// VTABLE 0x100dc1c8
// SIZE 0x28
class MxVariableTable : public MxHashTable<MxVariable*> {
public:
	MxVariableTable() { m_customDestructor = Destroy; }
	__declspec(dllexport) void SetVariable(const char* p_key, const char* p_value);
	__declspec(dllexport) void SetVariable(MxVariable* p_var);
	__declspec(dllexport) const char* GetVariable(const char* p_key);

	static void Destroy(MxVariable* p_obj) { p_obj->Destroy(); }

	virtual MxS8 Compare(MxVariable*, MxVariable*) override; // vtable+0x14
	virtual MxU32 Hash(MxVariable*) override;                // vtable+0x18
};

// VTABLE 0x100dc1b0 TEMPLATE
// class MxCollection<MxVariable *>

// VTABLE 0x100dc1e8 TEMPLATE
// class MxHashTable<MxVariable *>

#endif // MXVARIABLETABLE_H
