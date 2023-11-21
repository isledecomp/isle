#include "mxvariabletable.h"

// OFFSET: LEGO1 0x100afcd0 TEMPLATE
// MxCollection<MxVariable *>::Compare

// OFFSET: LEGO1 0x100afce0 TEMPLATE
// MxCollection<MxVariable *>::~MxCollection<MxVariable *>

// OFFSET: LEGO1 0x100afd30 TEMPLATE
// MxCollection<MxVariable *>::Destroy

// OFFSET: LEGO1 0x100afd40 TEMPLATE
// MxCollection<MxVariable *>::`scalar deleting destructor'

// OFFSET: LEGO1 0x100afdb0 TEMPLATE
// MxVariableTable::Destroy

// OFFSET: LEGO1 0x100afdc0 TEMPLATE
// MxHashTable<MxVariable *>::Hash

// OFFSET: LEGO1 0x100b0bd0 TEMPLATE
// MxHashTable<MxVariable *>::~MxHashTable<MxVariable *>

// OFFSET: LEGO1 0x100b0ca0 TEMPLATE
// MxHashTable<MxVariable *>::`scalar deleting destructor'

// OFFSET: LEGO1 0x100b7330
MxS8 MxVariableTable::Compare(MxVariable* p_var0, MxVariable* p_var1)
{
	return p_var0->GetKey()->Compare(*p_var1->GetKey());
}

// OFFSET: LEGO1 0x100b7370
MxU32 MxVariableTable::Hash(MxVariable* p_var)
{
	const char* str = p_var->GetKey()->GetData();
	MxU32 value = 0;

	for (int i = 0; str[i]; i++) {
		value += str[i];
	}

	return value;
}

// OFFSET: LEGO1 0x100b73a0
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

// OFFSET: LEGO1 0x100b7740
void MxVariableTable::SetVariable(MxVariable* p_var)
{
	MxHashTableCursor<MxVariable*> cursor(this);
	MxBool found = cursor.Find(p_var);

	if (found)
		cursor.DeleteMatch();

	MxHashTable<MxVariable*>::Add(p_var);
}

// OFFSET: LEGO1 0x100b78f0
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

// OFFSET: LEGO1 0x100b7ab0 TEMPLATE
// MxHashTable<MxVariable *>::Resize

// OFFSET: LEGO1 0x100b7b80 TEMPLATE
// MxHashTable<MxVariable *>::_NodeInsert
