set(eapp_bin hello-world)
set(eapp_src eapp/eapp_native.c)
set(host_bin hello-world-runner)
set(host_src host/host_native.cpp)
set(package_name "hello-world.ke")
set(package_script "./hello-world-runner hello-world")

if(RISCV32)
  set(eyrie_plugins "rv32 freemem")
else()
  set(eyrie_plugins "freemem")
endif()

# eapp

add_executable(${eapp_bin} ${eapp_src})
target_link_libraries(${eapp_bin} "-nostdlib -static -g" ${KEYSTONE_LIB_EAPP} ${KEYSTONE_LIB_EDGE})
set_target_properties(${eapp_bin}
  PROPERTIES LINK_FLAGS "-T ${CMAKE_CURRENT_SOURCE_DIR}/app.lds")

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

add_custom_command(TARGET ${host_bin} POST_BUILD
  COMMAND mkdir -p ../../overlay/root/${eapp_bin}
  COMMAND cp ${eapp_bin} ${host_bin} ../../overlay/root/${eapp_bin}/
  COMMAND python ../../../keystone-tools/patchEapp.py --in ../../overlay/root/${eapp_bin}/${eapp_bin}
  )

add_keystone_package(${eapp_bin}-package
  ${package_name}
  ${package_script}
  ${eapp_bin} ${host_bin})

add_custom_command(OUTPUT copy_file DEPENDS ${eapp_bin}-package
  COMMAND cp ${eapp_bin}-package  ../../overlay/root/examples
  )

# add package to the top-level target
add_dependencies(examples ${eapp_bin}-package)
