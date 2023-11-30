#include "mxvariabletable.h"

// TEMPLATE: LEGO1 0x100afcd0
// MxCollection<MxVariable *>::Compare

// TEMPLATE: LEGO1 0x100afce0
// MxCollection<MxVariable *>::~MxCollection<MxVariable *>

// TEMPLATE: LEGO1 0x100afd30
// MxCollection<MxVariable *>::Destroy

// SYNTHETIC: LEGO1 0x100afd40
// MxCollection<MxVariable *>::`scalar deleting destructor'

// TEMPLATE: LEGO1 0x100afdb0
// MxVariableTable::Destroy

// TEMPLATE: LEGO1 0x100afdc0
// MxHashTable<MxVariable *>::Hash

// TEMPLATE: LEGO1 0x100b0bd0
// MxHashTable<MxVariable *>::~MxHashTable<MxVariable *>

// SYNTHETIC: LEGO1 0x100b0ca0
// MxHashTable<MxVariable *>::`scalar deleting destructor'

// FUNCTION: LEGO1 0x100b7330
MxS8 MxVariableTable::Compare(MxVariable* p_var0, MxVariable* p_var1)
{
	return p_var0->GetKey()->Compare(*p_var1->GetKey());
}

// FUNCTION: LEGO1 0x100b7370
MxU32 MxVariableTable::Hash(MxVariable* p_var)
{
	const char* str = p_var->GetKey()->GetData();
	MxU32 value = 0;

	for (int i = 0; str[i]; i++) {
		value += str[i];
	}

	return value;
}

// FUNCTION: LEGO1 0x100b73a0
void MxVariableTable::SetVariable(const char* p_key, const char* p_value)
{
	MxHashTableCursor<MxVariable*> cursor(this);
	MxVariable* var = new MxVariable(p_key, p_value);

	if (cursor.Find(var)) {
		delete var;
		cursor.Current(var);
		var->SetValue(p_value);
	}
	else {
		MxHashTable<MxVariable*>::Add(var);
	}
}

// FUNCTION: LEGO1 0x100b7740
void MxVariableTable::SetVariable(MxVariable* p_var)
{
	MxHashTableCursor<MxVariable*> cursor(this);
	MxBool found = cursor.Find(p_var);

	if (found)
		cursor.DeleteMatch();

	MxHashTable<MxVariable*>::Add(p_var);
}

// FUNCTION: LEGO1 0x100b78f0
const char* MxVariableTable::GetVariable(const char* p_key)
{
	const char* value = "";
	MxHashTableCursor<MxVariable*> cursor(this);
	MxVariable* var = new MxVariable(p_key);

	MxBool found = cursor.Find(var);
	delete var;

	if (found) {
		cursor.Current(var);
		value = var->GetValue()->GetData();
	}

	return value;
}

// TEMPLATE: LEGO1 0x100b7ab0
// MxHashTable<MxVariable *>::Resize

// TEMPLATE: LEGO1 0x100b7b80
// MxHashTable<MxVariable *>::_NodeInsert
