add_library(platform
    alarm.c
)

set_target_properties(
    platform
    PROPERTIES
        C_STANDARD 99
        CXX_STANDARD 11
)

target_link_libraries(platform
    PRIVATE
        ot-config
    PUBLIC
#        -T${PROJECT_SOURCE_DIR}/src/cc2538.ld
        -Wl,--gc-sections -Wl,-Map=$<TARGET_PROPERTY:NAME>.map
)

target_compile_definitions(platform
    PUBLIC
        ${OT_PLATFORM_DEFINES}
)

target_compile_options(platform PRIVATE
    ${OT_CFLAGS}
)

