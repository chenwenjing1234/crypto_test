
include_directories(${ROOTDIR}/public/libcrypto/include)

link_directories(${ROOTDIR}/win_build/public/libcrypto/src/Debug
				 ${ROOTDIR}/third/openssl/lib/x64)

set(EXENAME "qinncrypttest")
set(DEPENDLIBS libqinncrypt.lib)
aux_source_directory(. SRC_LIST)
add_executable(${EXENAME} ${SRC_LIST})

target_link_libraries(${EXENAME} ${DEPENDLIBS})

set_target_properties(${LIBNAME} PROPERTIES FOLDER "test")