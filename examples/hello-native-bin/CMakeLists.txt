set(eapp_bin hello-native-bin)
set(eapp_src eapp/eapp_native.c)
set(host_bin hello-native-bin-runner)
set(host_src host/host_native.cpp)
set(package_name "hello-native-bin.ke")
set(package_script "./hello-native-bin-runner hello-native.bin")

if(RISCV32)
  set(eyrie_plugins "rv32 freemem")
else()
  set(eyrie_plugins "freemem")
endif()

# eapp

add_executable(${eapp_bin} ${eapp_src})
target_link_libraries(${eapp_bin} "-nostdlib -static" ${KEYSTONE_LIB_EAPP} ${KEYSTONE_LIB_EDGE})

target_include_directories(${eapp_bin}
  PUBLIC ${KEYSTONE_SDK_DIR}/include/app
  PUBLIC ${KEYSTONE_SDK_DIR}/include/edge)

# host

add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE})
# add -std=c++11 flag
set_target_properties(${host_bin}
  PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO
)
target_include_directories(${host_bin}
  PUBLIC ${KEYSTONE_SDK_DIR}/include/host
  PUBLIC ${KEYSTONE_SDK_DIR}/include/edge)

add_custom_command(OUTPUT ${eapp_bin}.bin DEPENDS ${eapp_bin}
  COMMAND riscv64-unknown-linux-gnu-objcopy -O binary ${eapp_bin} ${eapp_bin}.bin
)

# add target for packaging (see keystone.cmake)

add_keystone_package(${eapp_bin}-package
  ${package_name}
  ${package_script}
  ${eapp_bin}.bin ${host_bin})

add_custom_target("bin" ALL DEPENDS ${eapp_bin}.bin)
add_dependencies(${eapp_bin}-package "bin")

# add package to the top-level target
add_dependencies(examples ${eapp_bin}-package)

