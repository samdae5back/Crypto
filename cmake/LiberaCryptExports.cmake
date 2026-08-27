# Shared-library export and compiler-portability helpers for LiberaCrypt.
#
# Typical use, after all targets have been created:
#
#   include(cmake/LiberaCryptExports.cmake)
#   liberac_configure_exports(LiberaCrypt)
#   liberac_configure_portable_warnings(LiberaCrypt crypto_mldsa crypto_slhdsa)
#   liberac_configure_vendor_endianness(
#       SLHDSA_TARGET crypto_slhdsa
#       MLDSA_TARGET crypto_mldsa)
#
# liberac_configure_exports() accepts an optional second argument naming a
# different undecorated-symbol allowlist.

include_guard(GLOBAL)

set_property(GLOBAL PROPERTY LIBERAC_EXPORTS_DEFAULT_ALLOWLIST
    "${CMAKE_CURRENT_LIST_DIR}/liberacrypt_exports.txt")

function(_liberac_exports_read_allowlist output_variable allowlist)
    if(NOT EXISTS "${allowlist}")
        message(FATAL_ERROR "LiberaCrypt export allowlist does not exist: ${allowlist}")
    endif()

    file(STRINGS "${allowlist}" _liberac_export_lines)
    set(_liberac_export_symbols "")

    foreach(_liberac_export_line IN LISTS _liberac_export_lines)
        string(STRIP "${_liberac_export_line}" _liberac_export_line)
        if(_liberac_export_line STREQUAL "" OR _liberac_export_line MATCHES "^#")
            continue()
        endif()

        if(NOT _liberac_export_line MATCHES "^LIBERAC_[A-Z0-9_]+$")
            message(FATAL_ERROR
                "Invalid symbol '${_liberac_export_line}' in ${allowlist}; "
                "only undecorated LIBERAC_ C identifiers are permitted")
        endif()

        list(FIND _liberac_export_symbols "${_liberac_export_line}" _liberac_export_index)
        if(NOT _liberac_export_index EQUAL -1)
            message(FATAL_ERROR
                "Duplicate symbol '${_liberac_export_line}' in ${allowlist}")
        endif()
        list(APPEND _liberac_export_symbols "${_liberac_export_line}")
    endforeach()

    if(NOT _liberac_export_symbols)
        message(FATAL_ERROR "LiberaCrypt export allowlist is empty: ${allowlist}")
    endif()

    set(${output_variable} "${_liberac_export_symbols}" PARENT_SCOPE)
endfunction()

# Add comma-separated native-linker arguments without requiring CMake 3.13's
# target_link_options(). All supported Unix compiler drivers accept -Wl in the
# compatibility path used by this project (CMake >= 3.10).
function(_liberac_exports_add_linker_option target linker_option)
    if(COMMAND target_link_options)
        target_link_options(${target} PRIVATE "LINKER:${linker_option}")
    else()
        # LINK_FLAGS is an unstructured command fragment in CMake 3.10-3.12.
        # Keep explicit quotes in that fragment so an export-map path remains
        # one compiler-driver argument even when the build directory has
        # spaces. A double quote cannot occur in a generated Unix path, but
        # escape one defensively in caller-supplied options.
        string(REPLACE "\"" "\\\"" _crypto_escaped_linker_option
            "${linker_option}")
        set_property(TARGET ${target} APPEND_STRING PROPERTY LINK_FLAGS
            " \"-Wl,${_crypto_escaped_linker_option}\"")
    endif()
endfunction()

function(liberac_configure_exports target)
    if(NOT TARGET ${target})
        message(FATAL_ERROR "liberac_configure_exports: unknown target '${target}'")
    endif()

    get_target_property(_liberac_target_type ${target} TYPE)
    if(NOT _liberac_target_type STREQUAL "SHARED_LIBRARY" AND
       NOT _liberac_target_type STREQUAL "MODULE_LIBRARY")
        # Static archives have no dynamic export table and must not make their
        # consumers believe they are importing from a shared library.
        return()
    endif()

    if(ARGC GREATER 1)
        set(_liberac_allowlist "${ARGV1}")
    else()
        get_property(_liberac_allowlist GLOBAL
            PROPERTY LIBERAC_EXPORTS_DEFAULT_ALLOWLIST)
    endif()
    get_filename_component(_liberac_allowlist "${_liberac_allowlist}" ABSOLUTE)
    _liberac_exports_read_allowlist(_liberac_export_symbols "${_liberac_allowlist}")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${_liberac_allowlist}")

    # LIBERAC_API consumes these definitions. PUBLIC is intentional: a CMake
    # consumer of the shared target must see dllimport on Windows.
    target_compile_definitions(${target}
        PUBLIC LIBERAC_SHARED
        PRIVATE LIBERAC_BUILDING_LIBRARY)

    # Solaris, AIX, and HP-UX use linker allowlists because their legacy
    # compilers do not share GCC's visibility-switch behavior. Avoid emitting
    # -fvisibility=hidden on those targets; the platform block below is the
    # sole visibility authority there.
    if(NOT WIN32 AND
       NOT CMAKE_SYSTEM_NAME STREQUAL "SunOS" AND
       NOT CMAKE_SYSTEM_NAME STREQUAL "AIX" AND
       NOT CMAKE_SYSTEM_NAME STREQUAL "HP-UX")
        set_target_properties(${target} PROPERTIES
            C_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN YES)
    endif()

    string(MAKE_C_IDENTIFIER "${target}" _liberac_export_stem)
    set(_liberac_export_dir "${CMAKE_CURRENT_BINARY_DIR}/liberacrypt-exports")
    file(MAKE_DIRECTORY "${_liberac_export_dir}")

    if(WIN32)
        # __declspec(dllexport/dllimport) in inc/Def.h remains authoritative.
        # In particular, do not enable CMake's export-all object-file scan.
        set_target_properties(${target} PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS OFF)

    elseif(APPLE)
        # Mach-O's exported-symbol list uses linker names, hence the leading
        # underscore for every C identifier.
        set(_liberac_macos_exports
            "${_liberac_export_dir}/${_liberac_export_stem}_exports.list")
        file(WRITE "${_liberac_macos_exports}" "")
        foreach(_liberac_symbol IN LISTS _liberac_export_symbols)
            file(APPEND "${_liberac_macos_exports}" "_${_liberac_symbol}\n")
        endforeach()
        set_property(TARGET ${target} APPEND PROPERTY LINK_DEPENDS
            "${_liberac_macos_exports}")
        _liberac_exports_add_linker_option(${target}
            "-exported_symbols_list,${_liberac_macos_exports}")

    elseif(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
        # Use the legacy Solaris mapfile grammar retained by iotcc-new. It is
        # understood by both Solaris 10 and 11 link-editors.
        set(_liberac_solaris_map
            "${_liberac_export_dir}/${_liberac_export_stem}_exports.map")
        file(WRITE "${_liberac_solaris_map}" "{\n  global:\n")
        foreach(_liberac_symbol IN LISTS _liberac_export_symbols)
            file(APPEND "${_liberac_solaris_map}" "    ${_liberac_symbol};\n")
        endforeach()
        file(APPEND "${_liberac_solaris_map}" "  local:\n    *;\n};\n")
        set_property(TARGET ${target} APPEND PROPERTY LINK_DEPENDS
            "${_liberac_solaris_map}")
        _liberac_exports_add_linker_option(${target} "-M,${_liberac_solaris_map}")

    elseif(CMAKE_SYSTEM_NAME STREQUAL "AIX")
        # CMake 3.17 introduced the supported opt-out from its automatic
        # all-symbol export list. Older versions cannot guarantee this ABI.
        if(CMAKE_VERSION VERSION_LESS "3.17")
            message(FATAL_ERROR
                "Restricted AIX exports require CMake 3.17 or newer")
        endif()
        set_target_properties(${target} PROPERTIES AIX_EXPORT_ALL_SYMBOLS OFF)

        set(_liberac_aix_exports
            "${_liberac_export_dir}/${_liberac_export_stem}_exports.exp")
        file(WRITE "${_liberac_aix_exports}" "")
        foreach(_liberac_symbol IN LISTS _liberac_export_symbols)
            file(APPEND "${_liberac_aix_exports}" "${_liberac_symbol}\n")
        endforeach()
        set_property(TARGET ${target} APPEND PROPERTY LINK_DEPENDS
            "${_liberac_aix_exports}")
        _liberac_exports_add_linker_option(${target} "-bnoentry")
        _liberac_exports_add_linker_option(${target} "-bE:${_liberac_aix_exports}")

    elseif(CMAKE_SYSTEM_NAME STREQUAL "HP-UX")
        # HP ld's +e changes the link to an explicit export model: only names
        # supplied with +e are exported. This works for GCC and HP cc and avoids
        # iotcc-new's unsafe use of GCC's unrelated -B<prefix> option.
        foreach(_liberac_symbol IN LISTS _liberac_export_symbols)
            _liberac_exports_add_linker_option(${target} "+e,${_liberac_symbol}")
        endforeach()

    elseif(UNIX)
        # Linux and the other ELF targets supported by the project use a GNU-
        # style anonymous version script. The local wildcard also covers global
        # symbols originating in bundled object libraries.
        set(_liberac_elf_script
            "${_liberac_export_dir}/${_liberac_export_stem}_exports.map")
        file(WRITE "${_liberac_elf_script}" "{\n  global:\n")
        foreach(_liberac_symbol IN LISTS _liberac_export_symbols)
            file(APPEND "${_liberac_elf_script}" "    ${_liberac_symbol};\n")
        endforeach()
        file(APPEND "${_liberac_elf_script}" "  local:\n    *;\n};\n")
        set_property(TARGET ${target} APPEND PROPERTY LINK_DEPENDS
            "${_liberac_elf_script}")
        _liberac_exports_add_linker_option(${target}
            "--version-script,${_liberac_elf_script}")

    else()
        message(FATAL_ERROR
            "No restricted-export implementation for ${CMAKE_SYSTEM_NAME}")
    endif()
endfunction()

# Apply warning switches only where their spelling is known. Native SunPro,
# classic XL, and HP cc deliberately retain compiler defaults rather than being
# fed GCC-only -Wall/-Wextra/-pedantic options.
function(liberac_configure_portable_warnings)
    foreach(_liberac_warning_target IN LISTS ARGN)
        if(NOT TARGET ${_liberac_warning_target})
            message(FATAL_ERROR
                "liberac_configure_portable_warnings: unknown target "
                "'${_liberac_warning_target}'")
        endif()

        if(MSVC)
            target_compile_options(${_liberac_warning_target}
                PRIVATE /W4 /utf-8 /wd5105)
        elseif(CMAKE_C_COMPILER_ID MATCHES
               "^(GNU|Clang|AppleClang|IBMClang)$")
            target_compile_options(${_liberac_warning_target}
                PRIVATE -Wall -Wextra -pedantic)
        elseif(CMAKE_C_COMPILER_ID MATCHES
               "^(SunPro|XL|VisualAge|HP)$")
            # These compilers use different warning-option vocabularies.
        else()
            message(STATUS
                "LiberaCrypt: preserving warning defaults for C compiler "
                "${CMAKE_C_COMPILER_ID}")
        endif()
    endforeach()
endfunction()

# Configure bundled PQ implementations without including OS-specific endian
# headers in algorithm code. TestBigEndian works while cross-compiling because
# it inspects a compiled object instead of executing target code.
function(liberac_configure_vendor_endianness)
    set(_liberac_one_value_args SLHDSA_TARGET MLDSA_TARGET)
    cmake_parse_arguments(LIBERAC_ENDIAN "" "${_liberac_one_value_args}" "" ${ARGN})

    if(NOT LIBERAC_ENDIAN_SLHDSA_TARGET AND NOT LIBERAC_ENDIAN_MLDSA_TARGET)
        message(FATAL_ERROR
            "liberac_configure_vendor_endianness requires SLHDSA_TARGET and/or "
            "MLDSA_TARGET")
    endif()

    include(TestBigEndian)
    test_big_endian(_liberac_target_is_big_endian)

    if(LIBERAC_ENDIAN_MLDSA_TARGET)
        if(NOT TARGET ${LIBERAC_ENDIAN_MLDSA_TARGET})
            message(FATAL_ERROR
                "liberac_configure_vendor_endianness: unknown ML-DSA target "
                "'${LIBERAC_ENDIAN_MLDSA_TARGET}'")
        endif()
        if(_liberac_target_is_big_endian)
            target_compile_definitions(${LIBERAC_ENDIAN_MLDSA_TARGET}
                PRIVATE MLD_SYS_BIG_ENDIAN)
        else()
            target_compile_definitions(${LIBERAC_ENDIAN_MLDSA_TARGET}
                PRIVATE MLD_SYS_LITTLE_ENDIAN)
        endif()
    endif()

    if(LIBERAC_ENDIAN_SLHDSA_TARGET)
        if(NOT TARGET ${LIBERAC_ENDIAN_SLHDSA_TARGET})
            message(FATAL_ERROR
                "liberac_configure_vendor_endianness: unknown SLH-DSA target "
                "'${LIBERAC_ENDIAN_SLHDSA_TARGET}'")
        endif()

        include(CheckCSourceCompiles)
        check_c_source_compiles([=[
#if !defined(__BYTE_ORDER__) || !defined(__ORDER_BIG_ENDIAN__) || !defined(__ORDER_LITTLE_ENDIAN__)
#error compiler byte-order macros are unavailable
#endif
int main(void) { return 0; }
]=] _liberac_compiler_has_byte_order_macros)

        if(NOT _liberac_compiler_has_byte_order_macros)
            if(_liberac_target_is_big_endian)
                set(_liberac_byte_order 4321)
            else()
                set(_liberac_byte_order 1234)
            endif()
            target_compile_definitions(${LIBERAC_ENDIAN_SLHDSA_TARGET} PRIVATE
                __ORDER_LITTLE_ENDIAN__=1234
                __ORDER_BIG_ENDIAN__=4321
                __BYTE_ORDER__=${_liberac_byte_order})
        endif()
    endif()
endfunction()
