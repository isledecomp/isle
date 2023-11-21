// Sample for python unit tests
// Not part of the decomp

// A very simple class

class TestClass {
public:
  TestClass();
  virtual ~TestClass() override;

  virtual MxResult Tickle() override; // vtable+08

  // OFFSET: TEST 0x12345678
  inline const char* ClassName() const // vtable+0c
  {
    // 0xabcd1234
    return "TestClass";
  }

  // OFFSET: TEST 0xdeadbeef
  inline MxBool IsA(const char* name) const override // vtable+10
  {
    return !strcmp(name, TestClass::ClassName());
  }

private:
  int m_hello;
  int m_hiThere;
};
