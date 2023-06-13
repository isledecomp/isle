#ifndef MXVARIABLETABLE_H
#define MXVARIABLETABLE_H

class MxVariable;

class MxVariableTable
{
public:
  __declspec(dllexport) const char * GetVariable(const char *key);
  __declspec(dllexport) void SetVariable(MxVariable *var);
  __declspec(dllexport) void SetVariable(const char *key, const char *value);
};

#endif // MXVARIABLETABLE_H
