#ifndef MXLIST_H
#define MXLIST_H

#include "stlcompat.h"
#ifndef ISLE_COMPAT
#define LIST_T List<T>
#else
#define LIST_T list<T>
#endif

template <class T>
class MxList : public LIST_T
{
public:
  inline MxList() : LIST_T() {}
  inline ~MxList() {}
};

#endif // MXLIST_H
