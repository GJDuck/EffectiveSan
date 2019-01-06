append("-std=gnu++1z -msse4.2" CMAKE_CXX_FLAGS_RELEASE)

add_llvm_library(LLVMInstrumentation
  AddressSanitizer.cpp
  BoundsChecking.cpp
  DataFlowSanitizer.cpp
  GCOVProfiling.cpp
  MemorySanitizer.cpp
  IndirectCallPromotion.cpp
  Instrumentation.cpp
  InstrProfiling.cpp
  PGOInstrumentation.cpp
  SanitizerCoverage.cpp
  ThreadSanitizer.cpp
  EfficiencySanitizer.cpp
  EffectiveSan.cpp

  ADDITIONAL_HEADER_DIRS
  ${LLVM_MAIN_INCLUDE_DIR}/llvm/Transforms

  DEPENDS
  intrinsics_gen
  )
