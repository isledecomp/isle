#ifndef MXVARIABLETABLE_H
#define MXVARIABLETABLE_H

#include "mxtypes.h"
#include "mxcore.h"
#include "mxvariable.h"

template <class T>
class MxHashTableNode
{
public:
  MxHashTableNode<T>() {}
  MxHashTableNode<T>(T *p_obj, MxU32 p_hash)
  {
    m_obj = p_obj;
    m_hash = p_hash;
    m_prev = NULL;
    m_next = NULL;
  }

//private:
  T* m_obj;
  MxU32 m_hash;
  MxHashTableNode *m_prev;
  MxHashTableNode *m_next;
};

template <class T>
class MxHashTable : public MxCore
{
public:
  MxHashTable()
  {
    m_numSlots = 128;
    m_slots = new MxHashTableNode<T>*[128];
  }

  ~MxHashTable()
  {
    // TODO: Walk table to delete nodes?
    delete[] m_slots;
  }

  // OFFSET: LEGO1 0x100b7ab0
  void Resize()
  {
    // Save a reference to the current table
    // so we can walk nodes and re-insert
    MxHashTableNode<T> **old_table = m_slots;
    MxU32 old_size = m_numSlots;

    switch (m_option) {
      case 1: // flat increase by x
        m_numSlots = old_size + (int)m_increaseAmount;
        break;
      case 2: // increase by a factor of x
        m_numSlots = (int)(old_size * m_increaseFactor);
        break;
    }

    MxHashTableNode<T> **new_table = new MxHashTableNode<T>*[m_numSlots];
    // FIXME: order? m_numKeys set after `rep stosd`
    m_slots = new_table;
    m_numKeys = 0;
    memset(m_slots, 0, sizeof(MxHashTableNode<T> *) * m_numSlots);
    

    for (MxU32 i = 0; i < old_size; i++) {
      MxHashTableNode<T> *t = old_table[i];
      
      while (t) {
        MxHashTableNode<T> *next = t->m_next;
        int new_bucket = t->m_hash % m_numSlots;

        t->m_next = m_slots[new_bucket];

        // If the new bucket is not empty, make the reshuffled node
        // the new head of the bucket.
        if (m_slots[new_bucket])
          m_slots[new_bucket]->m_prev = t;
        
        m_slots[new_bucket] = t;
        t = next;
        m_numKeys++;
      }
    }

    delete[] old_table;
  }

  void Add(T* p_newobj)
  {
    MxU32 hash = Hash(p_newobj);
    MxHashTableNode<T> *node = new MxHashTableNode<T>(p_newobj, hash);

    int bucket = node->m_hash % m_numSlots;
    
    node->m_next = m_slots[bucket];
    
    if (m_slots[bucket])
      m_slots[bucket]->m_prev = node;

    m_slots[bucket] = node;
    m_numKeys++;
  }

  virtual MxS8 Compare(T*, T*);
  virtual MxU32 Hash(T*);

//private:
  int m_numKeys; // +0x8
  void (*m_customDestructor)(T*); // +0xc
  MxHashTableNode<T> **m_slots; // +0x10
  MxU32 m_numSlots; // +0x14
  int m_autoResizeRatio;
  int m_option; // +0x1c
  // FIXME: or FIXME? This qword is used as an integer or double depending
  // on the value of m_option. Hard to say whether this is how the devs
  // did it, but a simple cast in either direction doesn't match.
  union {
    MxS64 m_increaseAmount;
    double m_increaseFactor;
  };
};

template <class T>
class MxHashTableCursor : public MxCore
{
public:
  MxHashTableCursor(MxHashTable<T> *p_hashTable)
  {
    m_table = p_hashTable;
    m_match = NULL;
  }

  MxBool Find(T *p_obj)
  {
    MxU32 hash = m_table->Hash(p_obj);
    int bucket = hash % m_table->m_numSlots;

    MxHashTableNode<T> *t = m_table->m_slots[bucket];

    while (t) {
      if (t->m_hash == hash && !m_table->Compare(t->m_obj, p_obj))
        m_match = t;
      t = t->m_next;
    }

    return m_match != NULL;
  }

  void GetMatch(T **p_obj)
  {
    if (m_match) {
      *p_obj = m_match->m_obj;
    }
  }

  void DeleteMatch()
  {
    // Cut the matching node out of the linked list
    // by updating pointer references.

    if (m_match->m_prev) {
      m_match->m_prev->m_next = m_match->m_next;
    } else {
      // No "prev" node, so move "next" to the head of the list.
      int bucket = m_match->m_hash % m_table->m_numSlots;
      m_table->m_slots[bucket] = m_match->m_next;
    }

    if (m_match->m_next)
      m_match->m_next->m_prev = m_match->m_prev;

    m_table->m_customDestructor(m_match->m_obj);
    delete m_match;
    m_table->m_numKeys--;
  }

private:
  MxHashTable<T> *m_table;
  MxHashTableNode<T> *m_match; // type ?
};

// VTABLE 0x100dc1c8
// SIZE 0x28
class MxVariableTable : protected MxHashTable<MxVariable>
{
public:
  __declspec(dllexport) const char * GetVariable(const char *key);
  __declspec(dllexport) void SetVariable(MxVariable *var);
  __declspec(dllexport) void SetVariable(const char *key, const char *value);

  virtual MxS8 Compare(MxVariable *, MxVariable *); // +0x14
  virtual MxU32 Hash(MxVariable *); // +0x18
};

#endif // MXVARIABLETABLE_H
