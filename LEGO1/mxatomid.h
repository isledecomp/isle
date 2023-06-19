#ifndef MXATOMID_H
#define MXATOMID_H

enum LookupMode
{
};

class MxAtomId
{
public:
  __declspec(dllexport) MxAtomId(const char *, LookupMode);
  __declspec(dllexport) MxAtomId &operator=(const MxAtomId &id);
  __declspec(dllexport) ~MxAtomId();

  MxAtomId()
  {
    this->m_internal = 0;
  };

private:
  char *m_internal;
};

#endif // MXATOMID_H
