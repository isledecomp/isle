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

	// OFFSET: LEGO1 0x100afdb0
	static void Destroy(MxVariable* p_obj) { p_obj->Destroy(); }

	virtual MxBool Compare(MxVariable*, MxVariable*) override; // +0x14
	virtual MxU32 Hash(MxVariable*) override;                  // +0x18
};

// OFFSET: LEGO1 0x100afcd0 TEMPLATE
// MxCollection<MxVariable *>::Compare

// OFFSET: LEGO1 0x100afce0 TEMPLATE
// MxCollection<MxVariable *>::~MxCollection<MxVariable *>

// OFFSET: LEGO1 0x100afd30 TEMPLATE
// MxCollection<MxVariable *>::Destroy

// OFFSET: LEGO1 0x100afd40 TEMPLATE
// MxCollection<MxVariable *>::`scalar deleting destructor'

// OFFSET: LEGO1 0x100afdc0 TEMPLATE
// MxHashTable<MxVariable *>::Hash

// OFFSET: LEGO1 0x100b0bd0 TEMPLATE
// MxHashTable<MxVariable *>::~MxHashTable<MxVariable *>

// OFFSET: LEGO1 0x100b0ca0 TEMPLATE
// MxHashTable<MxVariable *>::`scalar deleting destructor'

// OFFSET: LEGO1 0x100b7ab0 TEMPLATE
// MxHashTable<MxVariable *>::Resize

// OFFSET: LEGO1 0x100b7b80 TEMPLATE
// MxHashTable<MxVariable *>::_NodeInsert

// VTABLE 0x100dc1b0 TEMPLATE
// class MxCollection<MxVariable *>

// VTABLE 0x100dc1e8 TEMPLATE
// class MxHashTable<MxVariable *>

#endif // MXVARIABLETABLE_H
