cmake_minimum_required(VERSION 2.8)

message (STATUS "************************** CRYPTO LIBS BUILD CONFIG PRINT MESSAGE ******************************")

#设置支持将多个项目组织到特定的文件夹 比如public目录下的工程都显示在public目录下
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set(ROOTDIR ${CMAKE_CURRENT_SOURCE_DIR})
	

add_subdirectory(public/libcrypto)
add_subdirectory(test)