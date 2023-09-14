#ifndef MXLIST_H
#define MXLIST_H

#include "mxtypes.h"
#include "mxcore.h"

template <class T>
// SIZE 0xc
class MxListEntry
{
public:
  MxListEntry() {}
  MxListEntry(T *p_obj, MxListEntry *p_prev) {
    m_obj = p_obj;
    m_prev = p_prev;
    m_next = NULL;
  }

  T *m_obj;
  MxListEntry *m_prev;
  MxListEntry *m_next;
};

// VTABLE 0x100d6350
// SIZE 0x10
template <class T>
class MxListParent : public MxCore
{
public:
  MxListParent() {
    m_count = 0;
    m_customDestructor = Destroy;
  }
  // OFFSET: LEGO1 0x1001cdd0
  virtual ~MxListParent() {}

  // OFFSET: LEGO1 0x1001cd30
  static void Destroy(T *) {};

  // OFFSET: LEGO1 0x1001cd20
  virtual MxS8 Compare(T *, T *) = 0;
protected:
  MxU32 m_count;                   // +0x8
  void (*m_customDestructor)(T *); // +0xc
};

// VTABLE 0x100d6368
// SIZE 0x18
template <class T>
class MxList : protected MxListParent<T>
{
public:
  MxList() {
    m_last = NULL;
    m_first = NULL;
  }

  virtual ~MxList();

  void Append(T*);

  friend class MxListCursor<T>;
protected:
  MxListEntry<T> *m_first; // +0x10
  MxListEntry<T> *m_last;  // +0x14
};

// VTABLE 0x100d6488
template <class T>
class MxListCursor : public MxCore
{
public:
  MxListCursor(MxList<T> *p_list) {
    m_list = p_list;
    m_match = NULL;
  }

  MxBool Find(T *p_obj) {
    for (m_match = m_list->m_first;
        m_match && m_list->Compare(m_match->m_obj, p_obj);
        m_match = m_match->m_next);

    return m_match != NULL;
  }

  void Detach() {
    MxListEntry<T> *m_prev = m_match->m_prev;
    MxListEntry<T> *m_next = m_match->m_next;

    if (m_prev)
      m_prev->m_next = m_next;
    else 
      m_list->m_first = m_next;

    if (m_next)
      m_next->m_prev = m_prev;
    else
      m_list->m_last = m_prev;

    delete m_match;
    m_list->m_count--;
    m_match = NULL;
  }

  MxBool Next(T*& p_obj) {
    if (!m_match)
      m_match = m_list->m_first;
    else
      m_match = m_match->m_next;

    if (m_match)
      p_obj = m_match->m_obj;

    return m_match != NULL;
  }
private:
  MxList<T> *m_list;
  MxListEntry<T> *m_match;
};

// Unclear purpose
// VTABLE 0x100d6530
template <class T>
class MxListCursorChild : public MxListCursor<T> 
{
public:
  MxListCursorChild(MxList<T> *p_list) : MxListCursor<T>(p_list) {}
};

// Unclear purpose
// VTABLE 0x100d6470
template <class T>
class MxListCursorChildChild : public MxListCursorChild<T>
{
public:
  MxListCursorChildChild(MxList<T> *p_list) : MxListCursorChild<T>(p_list) {}
};

template <class T>
// OFFSET: LEGO1 0x1001ce20
MxList<T>::~MxList()
{
  for (MxListEntry<T> *t = m_first;;) {
    if (!t)
      break;

    MxListEntry<T> *next = t->m_next;
    m_customDestructor(t->m_obj);
    delete t;
    t = next;
  }

  m_count = 0;
  m_last = NULL;
  m_first = NULL;
}

template <class T>
inline void MxList<T>::Append(T *p_newobj)
{
  MxListEntry<T> *currentLast = this->m_last;
  MxListEntry<T> *newEntry = new MxListEntry<T>(p_newobj, currentLast);

  if (currentLast)
    currentLast->m_next = newEntry;
  else
    this->m_first = newEntry;
    
  this->m_last = newEntry;
  this->m_count++;
}

#endif // MXLIST_H