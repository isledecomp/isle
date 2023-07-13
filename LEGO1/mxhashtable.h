#ifndef MXHASHTABLE_H
#define MXHASHTABLE_H

#include "mxtypes.h"
#include "mxcore.h"

#define HASH_TABLE_INIT_SIZE              128
#define HASH_TABLE_OPT_NO_EXPAND          0
#define HASH_TABLE_OPT_EXPAND_ADD         1
#define HASH_TABLE_OPT_EXPAND_MULTIPLY    2

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
    m_numSlots = HASH_TABLE_INIT_SIZE;
    m_slots = new MxHashTableNode<T>*[HASH_TABLE_INIT_SIZE];
    m_resizeOption = HASH_TABLE_OPT_NO_EXPAND;
  }

  ~MxHashTable()
  {
    // TODO: Walk table to delete nodes?
    delete[] m_slots;
  }

  // for convenience
  inline int GetBucket(int hash) {
    return hash % m_numSlots;
  }

  // OFFSET: LEGO1 0x100b7ab0
  void MxHashTable::Resize()
  {
    // Save a reference to the current table
    // so we can walk nodes and re-insert
    MxU32 old_size = m_numSlots;
    MxHashTableNode<T> **old_table = m_slots;

    switch (m_resizeOption) {
      case HASH_TABLE_OPT_EXPAND_ADD:
        m_numSlots = old_size + m_increaseAmount;
        break;
      case HASH_TABLE_OPT_EXPAND_MULTIPLY:
        m_numSlots = old_size * m_increaseFactor;
        break;
    }

    MxHashTableNode<T> **new_table = new MxHashTableNode<T>*[m_numSlots];
    // FIXME: order? m_numKeys set after `rep stosd`
    m_slots = new_table;
    memset(m_slots, 0, sizeof(MxHashTableNode<T> *) * m_numSlots);
    m_numKeys = 0;

    for (int i = 0; i != old_size; i++) {
      MxHashTableNode<T> *t = old_table[i];
      
      while (t) {
        MxHashTableNode<T> *next = t->m_next;
        _NodeInsert(t);
        t = next;
      }
    }

    delete[] old_table;
  }

  // OFFSET: LEGO1 0x100b7b80
  void MxHashTable::_NodeInsert(MxHashTableNode<T> *p_node) {
    int bucket = GetBucket(p_node->m_hash);
    
    p_node->m_next = m_slots[bucket];
    
    if (m_slots[bucket])
      m_slots[bucket]->m_prev = p_node;

    m_slots[bucket] = p_node;
    m_numKeys++;
  }

  void MxHashTable::Add(T* p_newobj)
  {
    if (m_resizeOption && ((m_numKeys + 1) / m_numSlots) > m_autoResizeRatio)
      MxHashTable<T>::Resize();

    MxU32 hash = Hash(p_newobj);
    MxHashTableNode<T> *node = new MxHashTableNode<T>(p_newobj, hash);

    MxHashTable<T>::_NodeInsert(node);
  }

  virtual MxS8 Compare(T*, T*);
  virtual MxU32 Hash(T*);

//private:
  MxU32 m_numKeys; // +0x8
  void (*m_customDestructor)(T*); // +0xc
  MxHashTableNode<T> **m_slots; // +0x10
  MxU32 m_numSlots; // +0x14
  MxU32 m_autoResizeRatio;
  int m_resizeOption; // +0x1c
  // FIXME: or FIXME? This qword is used as an integer or double depending
  // on the value of m_resizeOption. Hard to say whether this is how the devs
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
    int bucket = m_table->GetBucket(hash);

    MxHashTableNode<T> *t = m_table->m_slots[bucket];

    while (t) {
      if (t->m_hash == hash && !m_table->Compare(t->m_obj, p_obj))
        m_match = t;
      t = t->m_next;
    }

    return m_match != NULL;
  }

  void GetMatch(T*& p_obj)
  {
    if (m_match) {
      p_obj = m_match->m_obj;
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
      int bucket = m_table->GetBucket(m_match->m_hash);
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
  MxHashTableNode<T> *m_match;
};

#endif // MXHASHTABLE_H