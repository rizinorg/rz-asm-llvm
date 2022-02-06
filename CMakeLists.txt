cmake_minimum_required(VERSION 3.12)

project(rz-asm-llvm)

set(CMAKE_CXX_STANDARD 17)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti") # for subclassing of llvm classes

find_package(Rizin REQUIRED Asm)
set(RIZIN_INSTALL_PLUGDIR "${Rizin_PLUGINDIR}" CACHE STRING "Directory to install rizin plugins into")

add_library(asm_arm_llvm SHARED asm_arm_llvm.cpp)
llvm_map_components_to_libnames(llvm_libs MC AllTargetsAsmParsers AllTargetsDescs)
target_link_libraries(asm_arm_llvm ${llvm_libs} Rizin::Asm)
install(TARGETS asm_arm_llvm DESTINATION "${RIZIN_INSTALL_PLUGDIR}")
