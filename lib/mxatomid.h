#ifndef MXATOMID_H
#define MXATOMID_H

class MxAtomId
{
public:
  __declspec(dllexport) MxAtomId &operator=(const MxAtomId &id);
  __declspec(dllexport) ~MxAtomId();

  char *m_internal;

};

#endif // MXATOMID_H
