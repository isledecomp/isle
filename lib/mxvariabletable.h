#ifndef MXVARIABLETABLE_H
#define MXVARIABLETABLE_H

class MxVariableTable
{
public:
  __declspec(dllexport) void SetVariable(const char *key, const char *value);
};

#endif // MXVARIABLETABLE_H
