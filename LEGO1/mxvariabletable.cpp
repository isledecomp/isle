#include "mxvariabletable.h"

// OFFSET: LEGO1 0x100b7330
MxS8 MxVariableTable::Compare(MxVariable *p_var0, MxVariable *p_var1)
{
  return strcmp(p_var0->GetKey()->GetData(),
                p_var1->GetKey()->GetData());
}

// OFFSET: LEGO1 0x100b7370
MxU32 MxVariableTable::Hash(MxVariable *p_var)
{
  const char *str = p_var->GetKey()->GetData();
  MxU32 value = 0;
  
  for (int i = 0; str[i]; i++) {
    value += str[i];
  }

  return value;
}

// OFFSET: LEGO1 0x100b73a0
void MxVariableTable::SetVariable(const char *p_key, const char *p_value)
{
  MxHashTableCursor<MxVariable> cursor(this);
  MxVariable *var = new MxVariable(p_key, p_value);

  if (cursor.Find(var)) {
    delete var;
    cursor.GetMatch(&var);
    var->SetValue(p_value);
  } else {
    Add(var);
  }
}

// OFFSET: LEGO1 0x100b7740
void MxVariableTable::SetVariable(MxVariable *var)
{
  MxHashTableCursor<MxVariable> cursor(this);
  MxBool found = cursor.Find(var);

  if (found)
    cursor.DeleteMatch();

  Add(var);
}

// OFFSET: LEGO1 0x100b78f0
const char *MxVariableTable::GetVariable(const char *p_key)
{
  const char *value = "";
  MxHashTableCursor<MxVariable> cursor(this);
  MxVariable *var = new MxVariable(p_key);
  
  MxBool found = cursor.Find(var);
  delete var;
  
  if (found) {
    cursor.GetMatch(&var);
    value = var->GetValue()->GetData();
  }

  return value;
}
