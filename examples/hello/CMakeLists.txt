set(eapp_bin hello)
set(eapp_src eapp/hello.c)
set(host_bin hello-runner)
set(host_src host/host.cpp)
set(package_name "hello.ke")
set(package_script "./hello-runner hello")
# eapp

add_executable(${eapp_bin} ${eapp_src})
target_link_libraries(${eapp_bin} "-static")

# host

add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE})

# add target for packaging (see keystone.cmake)

add_keystone_package(${eapp_bin}-package
  ${package_name}
  ${package_script}
  ${eapp_bin} ${host_bin})

# add package to the top-level target
add_dependencies(examples ${eapp_bin}-package)
