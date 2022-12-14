cmake_minimum_required(VERSION 3.10)

project(ebpf_demos VERSION 0.1)

set(CMAKE_INSTALL_PREFIX "${PROJECT_SOURCE_DIR}/install")

#some custom vars 
set(BPF_KERN_SRC_FILES "${PROJECT_SOURCE_DIR}/src")
set(BPF_KERN_TARGETS "${CMAKE_INSTALL_PREFIX}")
#set(BIN_TARGETS "${PROJECT_SOURCE_DIR}/bin")
#set(CC_FILES "${PROJECT_SOURCE_DIR}/src/cc")

#add_definitions(-DNOBCC)


#add your libaries
#bpf
find_library(LIBBPF NAMES bpf libbpf REQUIRED HINTS "/usr/lib64" )
aux_source_directory("${BPF_KERN_SRC_FILES}" BPF_SRC_LIST)

#compile all .o files
add_library(ebpf_demo OBJECT ${BPF_SRC_LIST})

#target_include_directories(ebpf_demo PUBLIC ${BPF_KERN_SRC_FILES})

install(FILES $<TARGET_OBJECTS:ebpf_demo> DESTINATION "${BPF_KERN_TARGETS}")

set(CMAKE_C_FLAGS
    "${CMAKE_CXX_FLAGS} -Werror -g -O2 -target bpf"
)
