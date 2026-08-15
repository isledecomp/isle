include_guard(GLOBAL)
set(_ISLE_BYTE_IDENTITY_MODULE "${CMAKE_CURRENT_LIST_FILE}")

function(_isle_byte_identity_posix_quote value output)
  if("${value}" MATCHES "[\n\r]")
    message(FATAL_ERROR "Byte-identity launcher argument contains a newline")
  endif()
  string(REPLACE "'" "'\"'\"'" _quoted "${value}")
  set(${output} "'${_quoted}'" PARENT_SCOPE)
endfunction()

function(_isle_collect_byte_identity_build_graph
         directory targets_output directories_output imported_output)
  get_property(_local_targets DIRECTORY "${directory}" PROPERTY BUILDSYSTEM_TARGETS)
  # IMPORTED_TARGETS is directory scoped and is not included in
  # BUILDSYSTEM_TARGETS.  CMake 3.21 added the directory form used here; a
  # recursive inventory is required because imported link/interface payloads
  # may otherwise be introduced below the top-level directory unseen.
  get_property(_local_imported DIRECTORY "${directory}" PROPERTY IMPORTED_TARGETS)
  get_property(_child_directories DIRECTORY "${directory}" PROPERTY SUBDIRECTORIES)
  set(_all_targets ${_local_targets})
  set(_all_imported ${_local_imported})
  set(_all_directories "${directory}")
  foreach(_child_directory IN LISTS _child_directories)
    _isle_collect_byte_identity_build_graph(
      "${_child_directory}" _child_targets _descendant_directories
      _child_imported)
    list(APPEND _all_targets ${_child_targets})
    list(APPEND _all_imported ${_child_imported})
    list(APPEND _all_directories ${_descendant_directories})
  endforeach()
  list(REMOVE_DUPLICATES _all_imported)
  set(${targets_output} ${_all_targets} PARENT_SCOPE)
  set(${directories_output} ${_all_directories} PARENT_SCOPE)
  set(${imported_output} ${_all_imported} PARENT_SCOPE)
endfunction()

function(_isle_byte_identity_target_is_default target output)
  get_target_property(_target_excluded "${target}" EXCLUDE_FROM_ALL)
  if("${_target_excluded}" MATCHES "\\$<")
    message(FATAL_ERROR
      "Generator-expression EXCLUDE_FROM_ALL is unsupported for ${target}")
  endif()
  if(_target_excluded)
    set(${output} FALSE PARENT_SCOPE)
    return()
  endif()
  get_target_property(_target_directory "${target}" SOURCE_DIR)
  while(_target_directory)
    get_property(_directory_excluded DIRECTORY "${_target_directory}"
                 PROPERTY EXCLUDE_FROM_ALL)
    if("${_directory_excluded}" MATCHES "\\$<")
      message(FATAL_ERROR
        "Generator-expression directory EXCLUDE_FROM_ALL is unsupported: "
        "${_target_directory}")
    endif()
    if(_directory_excluded)
      set(${output} FALSE PARENT_SCOPE)
      return()
    endif()
    if(_target_directory STREQUAL PROJECT_SOURCE_DIR)
      break()
    endif()
    get_property(_target_directory DIRECTORY "${_target_directory}"
                 PROPERTY PARENT_DIRECTORY)
  endwhile()
  set(${output} TRUE PARENT_SCOPE)
endfunction()

function(_isle_byte_identity_source_language target source absolute_output language_output)
  get_target_property(_source_directory "${target}" SOURCE_DIR)
  if(IS_ABSOLUTE "${source}")
    get_filename_component(_absolute "${source}" ABSOLUTE)
  else()
    get_filename_component(_absolute "${source}" ABSOLUTE
                           BASE_DIR "${_source_directory}")
  endif()
  if(EXISTS "${_absolute}")
    file(REAL_PATH "${_absolute}" _absolute)
  endif()
  get_source_file_property(
    _declared_language "${source}" TARGET_DIRECTORY "${target}" LANGUAGE)
  get_source_file_property(
    _absolute_language "${_absolute}" TARGET_DIRECTORY "${target}" LANGUAGE)
  set(_languages)
  foreach(_language "${_declared_language}" "${_absolute_language}")
    if(_language AND NOT _language STREQUAL "NOTFOUND")
      list(APPEND _languages "${_language}")
    endif()
  endforeach()
  list(REMOVE_DUPLICATES _languages)
  list(LENGTH _languages _language_count)
  if(_language_count GREATER 1)
    message(FATAL_ERROR
      "Ambiguous effective source language for ${target}:${_absolute}: [${_languages}]")
  elseif(_language_count EQUAL 1)
    list(GET _languages 0 _effective_language)
  else()
    set(_effective_language "")
  endif()
  get_filename_component(_extension "${_absolute}" LAST_EXT)
  string(REGEX REPLACE "^[.]" "" _extension "${_extension}")
  if(NOT _effective_language)
    # LANGUAGE is populated only for an explicit source-file override.  For an
    # ordinary source, reproduce CMake's enabled-language extension mapping
    # from the toolchain-advertised lists.  The enabled-language registration
    # order resolves an overlap (notably `m`) the same way CMake does.
    get_property(_enabled_languages GLOBAL PROPERTY ENABLED_LANGUAGES)
    foreach(_language IN LISTS _enabled_languages)
      if(_language STREQUAL "C" OR _language STREQUAL "CXX")
        list(FIND CMAKE_${_language}_SOURCE_FILE_EXTENSIONS
             "${_extension}" _advertised_index)
        if(_advertised_index GREATER_EQUAL 0)
          set(_effective_language "${_language}")
        endif()
      endif()
    endforeach()
  endif()
  set(${absolute_output} "${_absolute}" PARENT_SCOPE)
  set(${language_output} "${_effective_language}" PARENT_SCOPE)
endfunction()

function(_isle_byte_identity_deferred_tail)
  get_property(_top_source GLOBAL PROPERTY ISLE_BYTE_IDENTITY_TOP_SOURCE)
  get_property(_tail_id GLOBAL PROPERTY ISLE_BYTE_IDENTITY_TAIL_ID)
  cmake_language(DEFER DIRECTORY "${_top_source}" GET_CALL_IDS _pending_calls)
  if(_tail_id)
    list(REMOVE_ITEM _pending_calls "${_tail_id}")
  endif()
  if(_pending_calls)
    # Calls deferred after isle_enable_byte_identity() must execute first.  A
    # deferred call may itself append more work, so keep moving this sentinel
    # to the true tail until the top-level queue is empty.
    cmake_language(
      DEFER DIRECTORY "${_top_source}" ID_VAR _next_tail_id
      CALL _isle_byte_identity_deferred_tail)
    set_property(GLOBAL PROPERTY ISLE_BYTE_IDENTITY_TAIL_ID "${_next_tail_id}")
    return()
  endif()
  _isle_finalize_byte_identity()
  set_property(GLOBAL PROPERTY ISLE_BYTE_IDENTITY_FINALIZED TRUE)
endfunction()

function(_isle_attest_archive_link_sequence target expected_occurrences)
  if(NOT TARGET "${target}")
    message(FATAL_ERROR
      "Third-party archive link contract references missing target ${target}")
  endif()
  set(_sequence ${ARGN})
  list(LENGTH _sequence _sequence_length)
  if(_sequence_length LESS 2)
    message(FATAL_ERROR "Third-party archive link sequence is incomplete")
  endif()
  get_target_property(_links "${target}" LINK_LIBRARIES)
  if(NOT _links)
    set(_links)
  endif()
  list(LENGTH _links _link_length)
  set(_observed 0)
  if(_link_length GREATER_EQUAL _sequence_length)
    math(EXPR _last_start "${_link_length} - ${_sequence_length}")
    foreach(_start RANGE 0 ${_last_start})
      set(_matches TRUE)
      math(EXPR _last_offset "${_sequence_length} - 1")
      foreach(_offset RANGE 0 ${_last_offset})
        math(EXPR _link_index "${_start} + ${_offset}")
        list(GET _links ${_link_index} _actual_token)
        list(GET _sequence ${_offset} _expected_token)
        if(NOT _actual_token STREQUAL _expected_token)
          set(_matches FALSE)
          break()
        endif()
      endforeach()
      if(_matches)
        math(EXPR _observed "${_observed} + 1")
      endif()
    endforeach()
  endif()
  if(NOT _observed EQUAL expected_occurrences)
    message(FATAL_ERROR
      "Third-party archive link sequence for ${target} occurs ${_observed} "
      "times; manifest requires ${expected_occurrences}")
  endif()
endfunction()

function(_isle_validate_byte_identity_compile_link_flags)
  if(NOT CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    message(FATAL_ERROR
      "ISLE_BYTE_IDENTICAL requires live CMAKE_BUILD_TYPE exactly RelWithDebInfo")
  endif()
  string(TOUPPER "${CMAKE_BUILD_TYPE}" _config_upper)
  get_property(_enabled_languages GLOBAL PROPERTY ENABLED_LANGUAGES)
  foreach(_language C CXX)
    list(FIND _enabled_languages "${_language}" _language_index)
    if(_language_index LESS 0)
      continue()
    endif()
    set(_config_flags_var "CMAKE_${_language}_FLAGS_${_config_upper}")
    set(_effective_compile_flags
      "${CMAKE_${_language}_FLAGS} ${${_config_flags_var}}")
    if(NOT _effective_compile_flags MATCHES "(^|[ \t])[-/]Zi([ \t]|$)")
      message(FATAL_ERROR
        "ISLE_BYTE_IDENTICAL requires exact /Zi for ${_language}")
    endif()
  endforeach()
  foreach(_link_kind EXE SHARED)
    set(_config_link_flags_var
      "CMAKE_${_link_kind}_LINKER_FLAGS_${_config_upper}")
    set(_effective_link_flags
      "${CMAKE_${_link_kind}_LINKER_FLAGS} ${${_config_link_flags_var}}")
    string(TOLOWER "${_effective_link_flags}" _effective_link_flags)
    if(_effective_link_flags MATCHES "(^|[ \t])[-/]debug([ :\t]|$)")
      message(FATAL_ERROR
        "ISLE_BYTE_IDENTICAL main ${_link_kind} link still enables /debug")
    endif()
  endforeach()
endfunction()

function(_isle_byte_identity_lexical_target_source target source output)
  get_target_property(_source_directory "${target}" SOURCE_DIR)
  if(IS_ABSOLUTE "${source}")
    get_filename_component(_absolute "${source}" ABSOLUTE)
  else()
    get_filename_component(_absolute "${source}" ABSOLUTE
                           BASE_DIR "${_source_directory}")
  endif()
  set(${output} "${_absolute}" PARENT_SCOPE)
endfunction()

function(_isle_apply_byte_identity_source_overlay_graph)
  if(NOT ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_PREBUILT_SOURCE_ARTIFACTS
     STREQUAL "forbidden")
    message(FATAL_ERROR "Source overlay prebuilt source artifacts are not forbidden")
  endif()
  if(NOT ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_ENABLED)
    if(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_OUTPUTS OR
       ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_INDICES OR
       ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_LINK_INDICES OR
       ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_FORBIDDEN_INTERFACES)
      message(FATAL_ERROR "Disabled source overlay emitted graph policy")
    endif()
    return()
  endif()

  foreach(_interface IN LISTS
      ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_FORBIDDEN_INTERFACES)
    if(DEFINED ${_interface})
      message(FATAL_ERROR
        "Legacy entropy interface remains defined in typed-overlay mode: ${_interface}")
    endif()
  endforeach()

  set(_expected_tu_index 0)
  set(_overlay_tu_paths)
  set(_overlay_tu_ordinals)
  foreach(_index IN LISTS ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_INDICES)
    if(NOT "${_index}" MATCHES "^(0|[1-9][0-9]*)$" OR
       NOT _index EQUAL _expected_tu_index)
      message(FATAL_ERROR
        "Source overlay generated-TU indices are not canonical")
    endif()
    math(EXPR _expected_tu_index "${_expected_tu_index} + 1")
    set(_prefix "ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_${_index}")
    list(FIND _overlay_tu_paths "${${_prefix}_PATH}" _duplicate_path)
    list(FIND _overlay_tu_ordinals
         "${${_prefix}_SOURCE_ORDINAL}" _duplicate_ordinal)
    list(FIND ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_OUTPUTS
         "${${_prefix}_PATH}" _owned_output)
    if(NOT _duplicate_path EQUAL -1 OR
       NOT _duplicate_ordinal EQUAL -1 OR
       _owned_output EQUAL -1)
      message(FATAL_ERROR
        "Source overlay generated-TU path/ordinal authority is duplicated or absent")
    endif()
    list(APPEND _overlay_tu_paths "${${_prefix}_PATH}")
    list(APPEND _overlay_tu_ordinals "${${_prefix}_SOURCE_ORDINAL}")
  endforeach()

  set(_overlay_target_count 0)
  foreach(_target lego1 beta10)
    if(NOT TARGET "${_target}")
      continue()
    endif()
    math(EXPR _overlay_target_count "${_overlay_target_count} + 1")
    get_target_property(_sources "${_target}" SOURCES)
    if(_sources MATCHES "-NOTFOUND$")
      set(_sources)
    endif()
    foreach(_index IN LISTS ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_INDICES)
      set(_prefix "ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_${_index}")
      list(LENGTH ${_prefix}_GENERATION_OPERATION_IDS
           _generation_operation_count)
      string(LENGTH "${${_prefix}_OUTPUT_SHA256}" _output_sha_length)
      string(LENGTH "${${_prefix}_OUTPUT_TOKEN_SHA256}"
             _output_token_sha_length)
      if(NOT "${${_prefix}_TARGET_FAMILY}" STREQUAL
             "list_targets_from_add_lego_libraries" OR
         NOT "${${_prefix}_LANGUAGE}" STREQUAL "CXX" OR
         NOT "${${_prefix}_TARGETS}" STREQUAL "lego1;beta10" OR
         _generation_operation_count LESS 1 OR
         NOT _output_sha_length EQUAL 64 OR
         NOT "${${_prefix}_OUTPUT_SHA256}" MATCHES "^[0-9a-f]+$" OR
         NOT _output_token_sha_length EQUAL 64 OR
         NOT "${${_prefix}_OUTPUT_TOKEN_SHA256}" MATCHES "^[0-9a-f]+$" OR
         NOT "${${_prefix}_OUTPUT_SIZE}" MATCHES "^[0-9]+$" OR
         NOT "${${_prefix}_OUTPUT_LINE_COUNT}" MATCHES "^[0-9]+$")
        message(FATAL_ERROR "Source overlay generated-TU policy differs")
      endif()
      set(_generated "${PROJECT_SOURCE_DIR}/${${_prefix}_PATH}")
      if(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_MATERIALIZED)
        # The runner materialized the effective view (generated TUs
        # included) into this source tree before configure.
        if(NOT EXISTS "${_generated}" OR IS_SYMLINK "${_generated}")
          message(FATAL_ERROR
            "Source overlay generated TU is not materialized: ${_generated}")
        endif()
      elseif(EXISTS "${_generated}" OR IS_SYMLINK "${_generated}")
        message(FATAL_ERROR
          "Source overlay generated-only TU unexpectedly exists: ${_generated}")
      endif()
      set(_generated_parent "${_generated}")
      while(NOT "${_generated_parent}" STREQUAL "${PROJECT_SOURCE_DIR}")
        get_filename_component(_next_parent "${_generated_parent}" DIRECTORY)
        string(FIND "${_next_parent}/" "${PROJECT_SOURCE_DIR}/"
               _source_root_prefix)
        if("${_next_parent}" STREQUAL "${_generated_parent}" OR
           NOT _source_root_prefix EQUAL 0)
          message(FATAL_ERROR
            "Source overlay generated-TU parent escapes the source root")
        endif()
        if(IS_SYMLINK "${_next_parent}")
          message(FATAL_ERROR
            "Source overlay generated-TU parent is redirected: ${_next_parent}")
        endif()
        set(_generated_parent "${_next_parent}")
      endwhile()
      math(EXPR _insert_index "${${_prefix}_SOURCE_ORDINAL} - 1")
      list(LENGTH _sources _source_count)
      if(_insert_index LESS 0 OR _insert_index GREATER _source_count)
        message(FATAL_ERROR
          "Source overlay TU ordinal is outside ${_target}: ${_generated}")
      endif()
      list(INSERT _sources ${_insert_index} "${_generated}")
      set_property(SOURCE "${_generated}" TARGET_DIRECTORY "${_target}"
        PROPERTY GENERATED TRUE)
      set_property(SOURCE "${_generated}" TARGET_DIRECTORY "${_target}"
        PROPERTY LANGUAGE CXX)
    endforeach()
    set_property(TARGET "${_target}" PROPERTY SOURCES ${_sources})

    foreach(_index IN LISTS ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_INDICES)
      set(_prefix "ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_${_index}")
      math(EXPR _seat "${${_prefix}_SOURCE_ORDINAL} - 1")
      math(EXPR _after_seat "${_seat} - 1")
      math(EXPR _before_seat "${_seat} + 1")
      list(LENGTH _sources _final_count)
      if(_after_seat LESS 0)
        message(FATAL_ERROR "Source overlay TU lacks its predecessor")
      endif()
      list(GET _sources ${_seat} _actual)
      list(GET _sources ${_after_seat} _actual_after)
      _isle_byte_identity_lexical_target_source(
        "${_target}" "${_actual}" _actual_abs)
      _isle_byte_identity_lexical_target_source(
        "${_target}" "${_actual_after}" _actual_after_abs)
      if(NOT "${_actual_abs}" STREQUAL
             "${PROJECT_SOURCE_DIR}/${${_prefix}_PATH}" OR
         NOT "${_actual_after_abs}" STREQUAL
             "${PROJECT_SOURCE_DIR}/${${_prefix}_INSERT_AFTER}")
        message(FATAL_ERROR
          "Source overlay TU graph seat differs on ${_target}: ${${_prefix}_PATH}")
      endif()
      if("${${_prefix}_INSERT_BEFORE}" STREQUAL "")
        # The tail contract is about C++ compile order: non-compiled sources
        # a target appends later (module-definition or resource scripts) may
        # legitimately trail the final generated TU, but no C/C++ TU may.
        math(EXPR _last_seat "${_final_count} - 1")
        if(NOT _seat EQUAL _last_seat)
          math(EXPR _trailing_first "${_seat} + 1")
          foreach(_trailing_seat RANGE ${_trailing_first} ${_last_seat})
            list(GET _sources ${_trailing_seat} _trailing_source)
            if("${_trailing_source}" MATCHES "\\.(c|cc|cpp|cxx)$")
              message(FATAL_ERROR
                "Source overlay final TU is not the C++ compile tail: "
                "${_trailing_source}")
            endif()
          endforeach()
        endif()
      else()
        if(_before_seat GREATER_EQUAL _final_count)
          message(FATAL_ERROR "Source overlay TU lacks its successor")
        endif()
        list(GET _sources ${_before_seat} _actual_before)
        _isle_byte_identity_lexical_target_source(
          "${_target}" "${_actual_before}" _actual_before_abs)
        if(NOT "${_actual_before_abs}" STREQUAL
               "${PROJECT_SOURCE_DIR}/${${_prefix}_INSERT_BEFORE}")
          message(FATAL_ERROR
            "Source overlay TU successor differs on ${_target}: ${${_prefix}_PATH}")
        endif()
      endif()
    endforeach()
  endforeach()
  if(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_INDICES AND
     _overlay_target_count EQUAL 0)
    message(FATAL_ERROR "Source overlay has no configured LEGO target instance")
  endif()

  set(_expected_link_index 0)
  foreach(_index IN LISTS ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_LINK_INDICES)
    if(NOT "${_index}" MATCHES "^(0|[1-9][0-9]*)$" OR
       NOT _index EQUAL _expected_link_index)
      message(FATAL_ERROR "Source overlay link indices are not canonical")
    endif()
    math(EXPR _expected_link_index "${_expected_link_index} + 1")
    set(_prefix "ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_LINK_${_index}")
    set(_target "${${_prefix}_TARGET}")
    if(NOT TARGET "${_target}" OR
       NOT "${${_prefix}_VISIBILITY}" STREQUAL "PRIVATE" OR
       NOT "${${_prefix}_ADMISSION_ID}" STREQUAL
           "config_private_dsound_probe_v1" OR
       NOT "${${_prefix}_SOURCE_OUTPUT}" STREQUAL
           "CONFIG/detectdx5.cpp" OR
       NOT "${${_prefix}_REQUIRED_OPERATION_IDS}" STREQUAL
           "op_3624_config_dsound_probe")
      message(FATAL_ERROR "Source overlay link target/visibility differs")
    endif()
    get_target_property(_links "${_target}" LINK_LIBRARIES)
    if(_links MATCHES "-NOTFOUND$")
      set(_links)
    endif()
    set(_seat_count 0)
    list(LENGTH _links _link_count)
    if(_link_count GREATER 1)
      math(EXPR _last_pair "${_link_count} - 2")
      foreach(_seat RANGE 0 ${_last_pair})
        math(EXPR _next "${_seat} + 1")
        list(GET _links ${_seat} _after)
        list(GET _links ${_next} _before)
        if("${_after}" STREQUAL "${${_prefix}_INSERT_AFTER}" AND
           "${_before}" STREQUAL "${${_prefix}_INSERT_BEFORE}")
          math(EXPR _seat_count "${_seat_count} + 1")
          set(_link_insert_index ${_next})
        endif()
      endforeach()
    endif()
    if(NOT _seat_count EQUAL 1)
      message(FATAL_ERROR "Source overlay link neighbor seat is not unique")
    endif()
    list(FIND _links "${${_prefix}_LIBRARY}" _existing_library)
    if(NOT _existing_library EQUAL -1)
      message(FATAL_ERROR "Source overlay link library already exists")
    endif()
    list(INSERT _links ${_link_insert_index} "${${_prefix}_LIBRARY}")
    set_property(TARGET "${_target}" PROPERTY LINK_LIBRARIES ${_links})
    get_target_property(_final_links "${_target}" LINK_LIBRARIES)
    list(FIND _final_links "${${_prefix}_LIBRARY}" _actual_link_seat)
    math(EXPR _expected_after_seat "${_actual_link_seat} - 1")
    math(EXPR _expected_before_seat "${_actual_link_seat} + 1")
    list(LENGTH _final_links _final_link_count)
    if(_actual_link_seat LESS 1 OR
       _expected_before_seat GREATER_EQUAL _final_link_count)
      message(FATAL_ERROR "Source overlay inserted link seat is incomplete")
    endif()
    list(GET _final_links ${_expected_after_seat} _actual_link_after)
    list(GET _final_links ${_expected_before_seat} _actual_link_before)
    if(NOT "${_actual_link_after}" STREQUAL "${${_prefix}_INSERT_AFTER}" OR
       NOT "${_actual_link_before}" STREQUAL "${${_prefix}_INSERT_BEFORE}")
      message(FATAL_ERROR "Source overlay inserted link seat differs")
    endif()
  endforeach()
endfunction()

function(_isle_byte_identity_source_overlay_authority source output)
  set(_authority CLEAN_SOURCE)
  foreach(_relative IN LISTS ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_OUTPUTS)
    if("${source}" STREQUAL "${PROJECT_SOURCE_DIR}/${_relative}")
      if(NOT _authority STREQUAL "CLEAN_SOURCE")
        message(FATAL_ERROR "Source overlay output path is duplicated")
      endif()
      set(_authority TYPED_SOURCE_OVERLAY)
    endif()
  endforeach()
  set(${output} "${_authority}" PARENT_SCOPE)
endfunction()

function(_isle_byte_identity_overlay_generated_source_allowed
    target source language ordinal output)
  set(_allowed FALSE)
  if(target STREQUAL "lego1" OR target STREQUAL "beta10")
    foreach(_index IN LISTS ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_INDICES)
      set(_prefix "ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_TU_${_index}")
      math(EXPR _expected_ordinal "${${_prefix}_SOURCE_ORDINAL} - 1")
      if("${source}" STREQUAL "${PROJECT_SOURCE_DIR}/${${_prefix}_PATH}" AND
         "${language}" STREQUAL "${${_prefix}_LANGUAGE}" AND
         "${ordinal}" STREQUAL "${_expected_ordinal}" AND
         "${${_prefix}_TARGET_FAMILY}" STREQUAL
         "list_targets_from_add_lego_libraries" AND
         target IN_LIST ${_prefix}_TARGETS)
        if(_allowed)
          message(FATAL_ERROR "Generated source has duplicate overlay authority")
        endif()
        set(_allowed TRUE)
      endif()
    endforeach()
  endif()
  set(${output} "${_allowed}" PARENT_SCOPE)
endfunction()

function(isle_enable_byte_identity manifest)
  if(CMAKE_VERSION VERSION_LESS 3.21)
    message(FATAL_ERROR
      "ISLE_BYTE_IDENTICAL requires CMake 3.21+ for recursive imported-target attestation")
  endif()
  if(NOT CMAKE_CURRENT_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    message(FATAL_ERROR
      "isle_enable_byte_identity() must be called from the top-level project directory")
  endif()
  get_property(_already_enabled GLOBAL PROPERTY ISLE_BYTE_IDENTITY_ENABLED)
  if(_already_enabled)
    message(FATAL_ERROR "The byte-identity framework may be enabled only once")
  endif()
  if(NOT ISLE_BYTE_IDENTICAL)
    message(FATAL_ERROR
      "byte_identity.cmake may be used only with ISLE_BYTE_IDENTICAL=ON")
  endif()
  if(CMAKE_HOST_WIN32)
    message(FATAL_ERROR
      "Native Windows BYTE_IDENTICAL production/CI execution is deferred and "
      "untested; only the backend compatibility seam is present")
  elseif(NOT CMAKE_HOST_UNIX)
    message(FATAL_ERROR
      "No byte-identity execution backend is declared for this host")
  endif()
  get_filename_component(_source_root "${PROJECT_SOURCE_DIR}" REALPATH)
  get_filename_component(_build_root "${CMAKE_BINARY_DIR}" REALPATH)
  file(RELATIVE_PATH _build_relative_to_source
       "${_source_root}" "${_build_root}")
  file(RELATIVE_PATH _source_relative_to_build
       "${_build_root}" "${_source_root}")
  if((NOT _build_relative_to_source STREQUAL ".." AND
      NOT _build_relative_to_source MATCHES "^\\.\\./") OR
     (NOT _source_relative_to_build STREQUAL ".." AND
      NOT _source_relative_to_build MATCHES "^\\.\\./"))
    message(FATAL_ERROR
      "The byte-identity build root must be disjoint from the source tree")
  endif()
  get_filename_component(_manifest "${manifest}" REALPATH
                         BASE_DIR "${PROJECT_SOURCE_DIR}")
  set(_controller_root "$ENV{ISLE_BYTE_IDENTITY_CONTROLLER_ROOT}")
  if(_controller_root)
    set(_tool "${_controller_root}/framework/tools/byte_identity.py")
    set(_backend_tool
        "${_controller_root}/framework/tools/byte_identity_backend.py")
    set(_entropy_tool "${_controller_root}/framework/tools/entropy.py")
  else()
    # Native configure fixtures have no hard-mode marker and deliberately
    # exercise this module in place.  The production top-level gate above
    # project() requires the hash-pinned controller root before reaching here.
    set(_tool "${PROJECT_SOURCE_DIR}/tools/byte_identity.py")
    set(_backend_tool "${PROJECT_SOURCE_DIR}/tools/byte_identity_backend.py")
    set(_entropy_tool "${PROJECT_SOURCE_DIR}/tools/entropy.py")
  endif()
  if(NOT EXISTS "${_manifest}" OR NOT EXISTS "${_tool}" OR
     NOT EXISTS "${_backend_tool}" OR
     NOT EXISTS "${_entropy_tool}")
    message(FATAL_ERROR "Byte-identity manifest or tools are missing")
  endif()
  # Avoid find_package(Python3): it creates Python3:: imported targets that
  # would become undeclared members of the terminal link-graph authority.
  # The native validator pins the executable bytes and exact version again.
  if(NOT Python3_EXECUTABLE)
    find_program(Python3_EXECUTABLE NAMES python3 REQUIRED)
  endif()
  if(NOT IS_ABSOLUTE "${Python3_EXECUTABLE}" OR
     NOT EXISTS "${Python3_EXECUTABLE}")
    message(FATAL_ERROR "Byte-identity Python must be an absolute executable")
  endif()
  execute_process(
    COMMAND "${Python3_EXECUTABLE}" -I -B -c
            "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"
    RESULT_VARIABLE _python_version_result)
  if(NOT _python_version_result EQUAL 0)
    message(FATAL_ERROR "ISLE_BYTE_IDENTICAL requires Python 3.10+")
  endif()
  set(_python_command "${Python3_EXECUTABLE}" -I -B)
  # Command attestation consumes the generator's authoritative command
  # database after generation; force it on before the deferred finalizer.
  set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE BOOL
      "Required by ISLE_BYTE_IDENTICAL command attestation" FORCE)
  # project() may already have populated a normal directory-scope value that
  # shadows the cache entry.  Publish the same authoritative setting to the
  # caller so generation actually emits the database for Make and Ninja.
  set(CMAKE_EXPORT_COMPILE_COMMANDS ON PARENT_SCOPE)

  # Invalidate a verdict immediately, before any code after this call (or any
  # later deferred callback) can make final graph attestation fail.
  execute_process(
    COMMAND ${_python_command} "${_tool}" invalidate
            --build-dir "${CMAKE_BINARY_DIR}"
    RESULT_VARIABLE _invalidate_result
    OUTPUT_VARIABLE _invalidate_output
    ERROR_VARIABLE _invalidate_error)
  if(NOT _invalidate_result EQUAL 0)
    message(FATAL_ERROR
      "Byte-identity stale-verdict invalidation failed (${_invalidate_result}):\n"
      "${_invalidate_output}${_invalidate_error}")
  endif()

  # Future targets inherit a launcher that invalidates and fails closed.  The
  # end-of-configure finalizer replaces it only after the target and every one
  # of its effective C/CXX sources have entered the authenticated inventory.
  set(_guard_launcher
    ${_python_command} "${_tool}" unfinalized-launch
    --build-dir "${CMAKE_BINARY_DIR}" --)
  set(CMAKE_C_COMPILER_LAUNCHER ${_guard_launcher} PARENT_SCOPE)
  set(CMAKE_CXX_COMPILER_LAUNCHER ${_guard_launcher} PARENT_SCOPE)

  # Generator convenience targets are formed before deferred finalization, so
  # close their direct compiler routes immediately in the caller's scope.
  set(_byte_identity_forbidden_convenience_rule
      "${CMAKE_COMMAND} -E false")
  foreach(_language C CXX)
    set(CMAKE_${_language}_CREATE_PREPROCESSED_SOURCE
        "${_byte_identity_forbidden_convenience_rule}" PARENT_SCOPE)
    set(CMAKE_${_language}_CREATE_ASSEMBLY_SOURCE
        "${_byte_identity_forbidden_convenience_rule}" PARENT_SCOPE)
  endforeach()

  set_property(GLOBAL PROPERTY ISLE_BYTE_IDENTITY_ENABLED TRUE)
  set_property(GLOBAL PROPERTY ISLE_BYTE_IDENTITY_MANIFEST "${_manifest}")
  set_property(GLOBAL PROPERTY ISLE_BYTE_IDENTITY_TOOL "${_tool}")
  set_property(GLOBAL PROPERTY ISLE_BYTE_IDENTITY_BACKEND_TOOL "${_backend_tool}")
  set_property(GLOBAL PROPERTY ISLE_BYTE_IDENTITY_ENTROPY_TOOL "${_entropy_tool}")
  set_property(GLOBAL PROPERTY ISLE_BYTE_IDENTITY_PYTHON "${Python3_EXECUTABLE}")
  set_property(GLOBAL PROPERTY ISLE_BYTE_IDENTITY_MODULE
               "${_ISLE_BYTE_IDENTITY_MODULE}")
  set_property(GLOBAL PROPERTY ISLE_BYTE_IDENTITY_TOP_SOURCE
               "${PROJECT_SOURCE_DIR}")
  set_property(GLOBAL PROPERTY ISLE_BYTE_IDENTITY_GUARD_LAUNCHER
               "${_guard_launcher}")
  cmake_language(
    DEFER DIRECTORY "${PROJECT_SOURCE_DIR}" ID_VAR _tail_id
    CALL _isle_byte_identity_deferred_tail)
  set_property(GLOBAL PROPERTY ISLE_BYTE_IDENTITY_TAIL_ID "${_tail_id}")
endfunction()

# Enable compiler-output COMDAT composition for ISLE_BYTE_IDENTICAL builds.
# The source-controlled manifest materializes each content-addressed
# declaration shape once and installs an atomic seed+donor compiler launcher
# with a build-wide four-process semaphore.  Only the strict equal-linked-span
# FPO closure is implemented; xdata/archive/image recipes are rejected by the
# native planner.
function(_isle_finalize_byte_identity)
  get_property(manifest GLOBAL PROPERTY ISLE_BYTE_IDENTITY_MANIFEST)
  get_property(_tool GLOBAL PROPERTY ISLE_BYTE_IDENTITY_TOOL)
  get_property(_backend_tool GLOBAL PROPERTY ISLE_BYTE_IDENTITY_BACKEND_TOOL)
  get_property(_entropy_tool GLOBAL PROPERTY ISLE_BYTE_IDENTITY_ENTROPY_TOOL)
  get_property(_pinned_python GLOBAL PROPERTY ISLE_BYTE_IDENTITY_PYTHON)
  get_property(_pinned_module GLOBAL PROPERTY ISLE_BYTE_IDENTITY_MODULE)
  get_property(_guard_launcher GLOBAL PROPERTY
               ISLE_BYTE_IDENTITY_GUARD_LAUNCHER)
  set(_ISLE_BYTE_IDENTITY_MODULE "${_pinned_module}")
  if(NOT ISLE_BYTE_IDENTICAL)
    message(FATAL_ERROR
      "byte_identity.cmake may be used only with ISLE_BYTE_IDENTICAL=ON")
  endif()
  if(NOT MSVC_FOR_DECOMP)
    message(FATAL_ERROR
      "ISLE_BYTE_IDENTICAL manifest composition requires the MSVC 4.20 toolchain")
  endif()
  if(NOT CMAKE_GENERATOR STREQUAL "Ninja" AND
     NOT CMAKE_GENERATOR STREQUAL "Unix Makefiles")
    message(FATAL_ERROR
      "ISLE_BYTE_IDENTICAL manifest composition supports only Ninja and Unix Makefiles")
  endif()
  if(CMAKE_VERSION VERSION_LESS 3.21)
    message(FATAL_ERROR
      "ISLE_BYTE_IDENTICAL requires CMake 3.21+ for recursive imported-target attestation")
  endif()
  # CMAKE_SYSTEM_NAME is Windows for this cross-build, so UNIX describes the
  # target and is false even though the launcher itself runs on macOS/Linux.
  if(NOT CMAKE_HOST_UNIX)
    message(FATAL_ERROR
      "The byte-identity launcher requires POSIX process-group and file-lock semantics")
  endif()
  get_filename_component(_source_root "${PROJECT_SOURCE_DIR}" REALPATH)
  get_filename_component(_build_root "${CMAKE_BINARY_DIR}" REALPATH)
  file(RELATIVE_PATH _build_relative_to_source
       "${_source_root}" "${_build_root}")
  file(RELATIVE_PATH _source_relative_to_build
       "${_build_root}" "${_source_root}")
  if((NOT _build_relative_to_source STREQUAL ".." AND
      NOT _build_relative_to_source MATCHES "^\\.\\./") OR
     (NOT _source_relative_to_build STREQUAL ".." AND
      NOT _source_relative_to_build MATCHES "^\\.\\./"))
    message(FATAL_ERROR
      "The byte-identity build root must be disjoint from the source tree")
  endif()
  get_property(_global_rule_launcher GLOBAL PROPERTY RULE_LAUNCH_COMPILE)
  if(_global_rule_launcher)
    message(FATAL_ERROR
      "Global/directory RULE_LAUNCH_COMPILE hooks are not permitted in a byte-identity build")
  endif()
  get_property(_global_link_launcher GLOBAL PROPERTY RULE_LAUNCH_LINK)
  if(_global_link_launcher)
    message(FATAL_ERROR
      "Global RULE_LAUNCH_LINK hooks are not permitted in a byte-identity build")
  endif()
  if(ISLE_INCLUDE_ENTROPY OR ISLE_TU_ENTROPY_MANIFEST)
    message(FATAL_ERROR
      "The byte-identity manifest owns entropy; disable ISLE_INCLUDE_ENTROPY and ISLE_TU_ENTROPY_MANIFEST")
  endif()
  if(NOT ISLE_PER_OBJECT_PDB)
    message(FATAL_ERROR
      "The byte-identity launcher requires ISLE_PER_OBJECT_PDB=ON for isolated compiler PDBs")
  endif()
  _isle_validate_byte_identity_compile_link_flags()
  get_property(_enabled_languages GLOBAL PROPERTY ENABLED_LANGUAGES)

  get_filename_component(_manifest "${manifest}" REALPATH)
  if(NOT EXISTS "${_manifest}")
    message(FATAL_ERROR "Missing fixed byte-identity manifest: ${_manifest}")
  endif()
  if(NOT EXISTS "${_tool}" OR NOT EXISTS "${_entropy_tool}")
    message(FATAL_ERROR "Byte-identity tools are missing")
  endif()
  if(NOT IS_ABSOLUTE "${Python3_EXECUTABLE}" OR
     NOT EXISTS "${Python3_EXECUTABLE}")
    message(FATAL_ERROR "Byte-identity Python must be an absolute executable")
  endif()
  if(NOT Python3_EXECUTABLE STREQUAL _pinned_python)
    message(FATAL_ERROR "Byte-identity Python changed after framework enablement")
  endif()
  set(_python_command "${Python3_EXECUTABLE}" -I -B)

  # CMake's direct .i/.s convenience rules are not ordinary object builds and
  # can bypass target launchers on supported generators. Replace the language
  # recipes with an unconditional native failure in both scopes; an empty
  # recipe is unsafe because Make/Ninja report a successful no-op. Compiler
  # argv also rejects /E, /P, and /FA fail-closed.
  set(_byte_identity_forbidden_convenience_rule
      "${CMAKE_COMMAND} -E false")
  foreach(_language C CXX)
    set(CMAKE_${_language}_CREATE_PREPROCESSED_SOURCE
        "${_byte_identity_forbidden_convenience_rule}")
    set(CMAKE_${_language}_CREATE_ASSEMBLY_SOURCE
        "${_byte_identity_forbidden_convenience_rule}")
    set(CMAKE_${_language}_CREATE_PREPROCESSED_SOURCE
        "${_byte_identity_forbidden_convenience_rule}" PARENT_SCOPE)
    set(CMAKE_${_language}_CREATE_ASSEMBLY_SOURCE
        "${_byte_identity_forbidden_convenience_rule}" PARENT_SCOPE)
  endforeach()

  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${_manifest}" "${_tool}" "${_backend_tool}" "${_entropy_tool}"
    "${_ISLE_BYTE_IDENTITY_MODULE}" "${Python3_EXECUTABLE}")
  set(_state_dir "${CMAKE_BINARY_DIR}/byte-identity")
  set(_plan "${_state_dir}/plan.cmake")
  execute_process(
    COMMAND ${_python_command} "${_tool}" plan
            --manifest "${_manifest}"
            --source-dir "${PROJECT_SOURCE_DIR}"
            --build-dir "${CMAKE_BINARY_DIR}"
            --compiler "${CMAKE_CXX_COMPILER}"
            --compiler-id "${CMAKE_CXX_COMPILER_ID}"
            --compiler-version "${CMAKE_CXX_COMPILER_VERSION}"
            --generator "${CMAKE_GENERATOR}"
            --output "${_plan}"
            --emit-cmake
    RESULT_VARIABLE _plan_result
    OUTPUT_VARIABLE _plan_output
    ERROR_VARIABLE _plan_error
  )
  if(NOT _plan_result EQUAL 0 OR NOT EXISTS "${_plan}")
    message(FATAL_ERROR
      "Byte-identity manifest planning failed (${_plan_result}):\n${_plan_output}${_plan_error}")
  endif()
  unset(ISLE_BYTE_IDENTITY_PLAN_COMPLETE)
  cmake_language(EVAL CODE "${_plan_output}")
  if(NOT ISLE_BYTE_IDENTITY_PLAN_COMPLETE)
    message(FATAL_ERROR "Direct byte-identity plan fragment is incomplete")
  endif()
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    ${ISLE_BYTE_IDENTITY_POLICY_INPUTS})
  if(NOT ISLE_BYTE_IDENTITY_PHASE STREQUAL "compiler_output_comdat_v1")
    message(FATAL_ERROR "Generated byte-identity plan has an unsupported phase")
  endif()
  if(NOT ISLE_BYTE_IDENTITY_EXECUTION_BACKEND STREQUAL
         "posix_wine_virtual_z_v1")
    message(FATAL_ERROR
      "Generated byte-identity plan selected an unsupported execution backend: "
      "${ISLE_BYTE_IDENTITY_EXECUTION_BACKEND}")
  endif()
  if(NOT ISLE_BYTE_IDENTITY_COMPLETION STREQUAL
         "object_composition_enabled_final_gates_incomplete" AND
     NOT ISLE_BYTE_IDENTITY_COMPLETION STREQUAL "planned_not_composed")
    message(FATAL_ERROR "Generated plan improperly claims byte-identity completion")
  endif()
  _isle_apply_byte_identity_source_overlay_graph()

  # The manifest target registry is the build-wide safety boundary. Discover
  # every non-imported build-system target that owns a C/C++ source and require
  # exact equality: no project compile may bypass the atomic launcher and its
  # global four-process semaphore.
  _isle_collect_byte_identity_build_graph(
    "${PROJECT_SOURCE_DIR}" _build_targets _build_directories
    _build_imported_targets)
  set(_authorized_archive_targets)
  foreach(_archive_index IN LISTS ISLE_BYTE_IDENTITY_ARCHIVE_INDICES)
    set(_archive_prefix "ISLE_BYTE_IDENTITY_ARCHIVE_${_archive_index}")
    list(APPEND _authorized_archive_targets
         "${${_archive_prefix}_IMPORTED_TARGET}")
  endforeach()
  list(REMOVE_DUPLICATES _authorized_archive_targets)
  set(_declared_imported_targets)
  foreach(_imported_index IN LISTS ISLE_BYTE_IDENTITY_IMPORTED_TARGET_INDICES)
    set(_imported_prefix
        "ISLE_BYTE_IDENTITY_IMPORTED_TARGET_${_imported_index}")
    list(APPEND _declared_imported_targets "${${_imported_prefix}_NAME}")
  endforeach()
  list(APPEND _declared_imported_targets ${_authorized_archive_targets})
  list(REMOVE_DUPLICATES _declared_imported_targets)
  list(SORT _declared_imported_targets)
  list(SORT _build_imported_targets)
  if(NOT "${_build_imported_targets}" STREQUAL "${_declared_imported_targets}")
    message(FATAL_ERROR
      "Recursive imported-target universe differs from the manifest; "
      "declared=[${_declared_imported_targets}] "
      "discovered=[${_build_imported_targets}]")
  endif()
  foreach(_imported_index IN LISTS ISLE_BYTE_IDENTITY_IMPORTED_TARGET_INDICES)
    set(_imported_prefix
        "ISLE_BYTE_IDENTITY_IMPORTED_TARGET_${_imported_index}")
    set(_imported_target "${${_imported_prefix}_NAME}")
    if(NOT TARGET "${_imported_target}")
      message(FATAL_ERROR
        "Manifest imported target is absent: ${_imported_target}")
    endif()
    get_target_property(_observed_imported "${_imported_target}" IMPORTED)
    get_target_property(_observed_type "${_imported_target}" TYPE)
    get_target_property(_observed_global "${_imported_target}" IMPORTED_GLOBAL)
    if(NOT _observed_imported OR
       NOT "${_observed_type}" STREQUAL "${${_imported_prefix}_TYPE}" OR
       NOT "${_observed_global}" STREQUAL "${${_imported_prefix}_GLOBAL}")
      message(FATAL_ERROR
        "Imported target identity/type/global surface differs: ${_imported_target}")
    endif()
    get_target_property(_observed_location "${_imported_target}"
                        IMPORTED_LOCATION)
    if(_observed_location MATCHES "-NOTFOUND$")
      set(_observed_location "")
    endif()
    if(NOT "${_observed_location}" STREQUAL
       "${${_imported_prefix}_LOCATION}")
      message(FATAL_ERROR
        "Imported target location differs: ${_imported_target}")
    endif()
    foreach(_surface
        INTERFACE_LINK_LIBRARIES
        INTERFACE_LINK_LIBRARIES_DIRECT
        INTERFACE_LINK_LIBRARIES_DIRECT_EXCLUDE
        INTERFACE_LINK_OPTIONS
        INTERFACE_LINK_DIRECTORIES
        INTERFACE_INCLUDE_DIRECTORIES
        INTERFACE_SYSTEM_INCLUDE_DIRECTORIES
        INTERFACE_COMPILE_OPTIONS
        INTERFACE_COMPILE_DEFINITIONS
        INTERFACE_COMPILE_FEATURES
        INTERFACE_SOURCES)
      get_target_property(_observed_surface "${_imported_target}" "${_surface}")
      if(_observed_surface MATCHES "-NOTFOUND$")
        set(_observed_surface)
      endif()
      set(_expected_surface "${${_imported_prefix}_${_surface}}")
      if(NOT "${_observed_surface}" STREQUAL "${_expected_surface}")
        message(FATAL_ERROR
          "Imported target ${_imported_target} ${_surface} differs; "
          "expected=[${_expected_surface}] observed=[${_observed_surface}]")
      endif()
    endforeach()
    foreach(_surface
        IMPORTED_IMPLIB
        IMPORTED_LINK_DEPENDENT_LIBRARIES
        IMPORTED_LINK_INTERFACE_LIBRARIES
        IMPORTED_LINK_INTERFACE_LANGUAGES
        IMPORTED_LINK_INTERFACE_MULTIPLICITY)
      get_target_property(_observed_surface "${_imported_target}" "${_surface}")
      if(_observed_surface AND NOT _observed_surface MATCHES "-NOTFOUND$")
        message(FATAL_ERROR
          "Imported target ${_imported_target} has undeclared ${_surface}")
      endif()
    endforeach()
    get_target_property(_imported_configurations "${_imported_target}"
                        IMPORTED_CONFIGURATIONS)
    if(_imported_configurations AND
       NOT _imported_configurations MATCHES "-NOTFOUND$")
      message(FATAL_ERROR
        "Imported target ${_imported_target} has undeclared IMPORTED_CONFIGURATIONS")
    endif()
    string(TOUPPER "${CMAKE_BUILD_TYPE}" _active_imported_config)
    foreach(_surface
        IMPORTED_LOCATION IMPORTED_IMPLIB
        IMPORTED_LINK_DEPENDENT_LIBRARIES
        IMPORTED_LINK_INTERFACE_LIBRARIES
        IMPORTED_LINK_INTERFACE_LANGUAGES
        IMPORTED_LINK_INTERFACE_MULTIPLICITY
        MAP_IMPORTED_CONFIG)
      get_target_property(
        _observed_surface "${_imported_target}"
        "${_surface}_${_active_imported_config}")
      if(_observed_surface AND NOT _observed_surface MATCHES "-NOTFOUND$")
        message(FATAL_ERROR
          "Imported target ${_imported_target} has undeclared active-config "
          "${_surface}_${_active_imported_config}")
      endif()
    endforeach()
  endforeach()
  # Archive-only native materialization fixtures have no final image/link
  # contract, but their one explicitly authorized imported archive remains a
  # fully attested non-transitive target rather than a generic bypass.
  # Generated indices are zero-based; a singleton list containing "0" is a
  # structurally nonempty list even though CMake's boolean grammar calls its
  # value false.
  list(LENGTH ISLE_BYTE_IDENTITY_IMPORTED_TARGET_INDICES
       _imported_target_count)
  foreach(_archive_index IN LISTS ISLE_BYTE_IDENTITY_ARCHIVE_INDICES)
    set(_archive_prefix "ISLE_BYTE_IDENTITY_ARCHIVE_${_archive_index}")
    set(_archive_target "${${_archive_prefix}_IMPORTED_TARGET}")
    if(_imported_target_count GREATER 0)
      # Final-image manifests validate these same targets through the exact
      # terminal imported-target contracts above.
      continue()
    endif()
    get_target_property(_archive_imported "${_archive_target}" IMPORTED)
    get_target_property(_archive_type "${_archive_target}" TYPE)
    get_target_property(_archive_global "${_archive_target}" IMPORTED_GLOBAL)
    get_target_property(_archive_location "${_archive_target}" IMPORTED_LOCATION)
    if(NOT _archive_imported OR NOT _archive_global OR
       NOT _archive_type STREQUAL "STATIC_LIBRARY" OR
       NOT _archive_location STREQUAL "${${_archive_prefix}_SOURCE}")
      message(FATAL_ERROR
        "Authorized archive-only imported target surface differs: ${_archive_target}")
    endif()
    foreach(_surface
        INTERFACE_LINK_LIBRARIES INTERFACE_LINK_LIBRARIES_DIRECT
        INTERFACE_LINK_LIBRARIES_DIRECT_EXCLUDE INTERFACE_LINK_OPTIONS
        INTERFACE_LINK_DIRECTORIES INTERFACE_INCLUDE_DIRECTORIES
        INTERFACE_SYSTEM_INCLUDE_DIRECTORIES INTERFACE_COMPILE_OPTIONS
        INTERFACE_COMPILE_DEFINITIONS INTERFACE_COMPILE_FEATURES
        INTERFACE_SOURCES)
      get_target_property(_archive_surface "${_archive_target}" "${_surface}")
      if(_archive_surface AND NOT _archive_surface MATCHES "-NOTFOUND$")
        message(FATAL_ERROR
          "Authorized archive-only imported target ${_archive_target} has "
          "undeclared ${_surface}")
      endif()
    endforeach()
    get_target_property(_archive_configurations "${_archive_target}"
                        IMPORTED_CONFIGURATIONS)
    if(_archive_configurations AND
       NOT _archive_configurations MATCHES "-NOTFOUND$")
      message(FATAL_ERROR
        "Authorized archive-only target has undeclared IMPORTED_CONFIGURATIONS")
    endif()
    string(TOUPPER "${CMAKE_BUILD_TYPE}" _active_archive_config)
    foreach(_surface
        IMPORTED_LOCATION IMPORTED_IMPLIB
        IMPORTED_LINK_DEPENDENT_LIBRARIES
        IMPORTED_LINK_INTERFACE_LIBRARIES
        IMPORTED_LINK_INTERFACE_LANGUAGES
        IMPORTED_LINK_INTERFACE_MULTIPLICITY
        MAP_IMPORTED_CONFIG)
      get_target_property(
        _archive_surface "${_archive_target}"
        "${_surface}_${_active_archive_config}")
      if(_archive_surface AND NOT _archive_surface MATCHES "-NOTFOUND$")
        message(FATAL_ERROR
          "Authorized archive-only target has undeclared active-config "
          "${_surface}_${_active_archive_config}")
      endif()
    endforeach()
  endforeach()
  set(_user_targets)
  set(_default_user_targets)
  set(_target_inventory_arguments)
  set(_graph_count_arguments)
  set(_graph_item_arguments)
  set(_standard_library_arguments)
  foreach(_user_target IN LISTS _build_targets)
    if(_user_target MATCHES "^byte-identity-")
      message(FATAL_ERROR
        "Project target uses the reserved byte-identity namespace: ${_user_target}")
    endif()
    get_property(_manual_dependencies TARGET "${_user_target}"
                 PROPERTY MANUALLY_ADDED_DEPENDENCIES)
    foreach(_manual_dependency IN LISTS _manual_dependencies)
      if(_manual_dependency MATCHES "^byte-identity-")
        message(FATAL_ERROR
          "Project target ${_user_target} has an unsupported/cyclic byte-identity dependency")
      endif()
    endforeach()
    get_property(_existing_link_rule TARGET "${_user_target}"
                 PROPERTY RULE_LAUNCH_LINK)
    if(_existing_link_rule)
      message(FATAL_ERROR
        "Target RULE_LAUNCH_LINK hook is not permitted: ${_user_target}")
    endif()
    get_target_property(_user_link_libraries "${_user_target}" LINK_LIBRARIES)
    foreach(_user_link_item IN LISTS _user_link_libraries)
      if("${_user_link_item}" MATCHES "TARGET_OBJECTS:" OR
         "${_user_link_item}" MATCHES "(^|[/\\])[^/\\]+\.(obj|o|res|lib|a)$")
        message(FATAL_ERROR
          "Opaque object/resource/archive link expression is forbidden on ${_user_target}: ${_user_link_item}")
      endif()
    endforeach()
    get_target_property(_user_interface_sources "${_user_target}"
                        INTERFACE_SOURCES)
    if(_user_interface_sources)
      message(FATAL_ERROR
        "INTERFACE_SOURCES are unsupported because they can inject an unowned compile/link payload: ${_user_target}")
    endif()
    get_target_property(_user_static_options "${_user_target}"
                        STATIC_LIBRARY_OPTIONS)
    if(_user_static_options)
      message(FATAL_ERROR
        "STATIC_LIBRARY_OPTIONS can inject unaudited archive payloads: ${_user_target}")
    endif()
    list(APPEND _user_targets "${_user_target}")
    get_target_property(_user_target_type "${_user_target}" TYPE)
    if(NOT _user_target_type MATCHES
       "^(STATIC_LIBRARY|SHARED_LIBRARY|MODULE_LIBRARY|EXECUTABLE|UTILITY|INTERFACE_LIBRARY)$")
      message(FATAL_ERROR
        "Unsupported byte-identity target type ${_user_target_type}: ${_user_target}")
    endif()
    _isle_byte_identity_target_is_default(
      "${_user_target}" _user_target_is_default)
    if(_user_target_is_default)
      list(APPEND _default_user_targets "${_user_target}")
      set(_user_target_default_text TRUE)
    else()
      set(_user_target_default_text FALSE)
    endif()
    list(APPEND _target_inventory_arguments
      --target-entry "${_user_target}" "${_user_target_type}"
                     "${_user_target_default_text}")
    foreach(_graph_property
        LINK_LIBRARIES
        INTERFACE_LINK_LIBRARIES
        INTERFACE_LINK_LIBRARIES_DIRECT
        INTERFACE_LINK_LIBRARIES_DIRECT_EXCLUDE
        LINK_OPTIONS
        INTERFACE_LINK_OPTIONS
        LINK_DIRECTORIES
        INTERFACE_LINK_DIRECTORIES)
      get_target_property(_graph_values "${_user_target}" "${_graph_property}")
      if(_graph_values MATCHES "-NOTFOUND$")
        set(_graph_values)
      endif()
      list(LENGTH _graph_values _graph_count)
      list(APPEND _graph_count_arguments
        --graph-count "${_user_target}" "${_graph_property}" "${_graph_count}")
      foreach(_graph_value IN LISTS _graph_values)
        list(APPEND _graph_item_arguments
          --graph-item "${_user_target}" "${_graph_property}" "${_graph_value}")
      endforeach()
    endforeach()
    foreach(_graph_property LINK_FLAGS LINK_LIBRARIES_STRATEGY
            LINK_INTERFACE_MULTIPLICITY)
      get_target_property(_graph_value "${_user_target}" "${_graph_property}")
      if(_graph_value MATCHES "-NOTFOUND$")
        set(_graph_value "")
      endif()
      if(_graph_value)
        list(APPEND _graph_count_arguments
          --graph-count "${_user_target}" "${_graph_property}" 1)
        list(APPEND _graph_item_arguments
          --graph-item "${_user_target}" "${_graph_property}" "${_graph_value}")
      else()
        list(APPEND _graph_count_arguments
          --graph-count "${_user_target}" "${_graph_property}" 0)
      endif()
    endforeach()
    string(TOUPPER "${CMAKE_BUILD_TYPE}" _graph_config_upper)
    foreach(_graph_config_property
        LINK_FLAGS LINK_INTERFACE_LIBRARIES LINK_INTERFACE_MULTIPLICITY)
      get_target_property(_graph_value "${_user_target}"
                          "${_graph_config_property}_${_graph_config_upper}")
      if(_graph_value MATCHES "-NOTFOUND$")
        set(_graph_value "")
      endif()
      if(_graph_value)
        list(APPEND _graph_count_arguments
          --graph-count "${_user_target}"
          "${_graph_config_property}_CONFIG" 1)
        list(APPEND _graph_item_arguments
          --graph-item "${_user_target}"
          "${_graph_config_property}_CONFIG" "${_graph_value}")
      else()
        list(APPEND _graph_count_arguments
          --graph-count "${_user_target}"
          "${_graph_config_property}_CONFIG" 0)
      endif()
    endforeach()
  endforeach()
  list(REMOVE_DUPLICATES _user_targets)
  list(REMOVE_DUPLICATES _default_user_targets)
  list(LENGTH ISLE_BYTE_IDENTITY_IMAGE_INDICES _inventory_image_count)
  if(_inventory_image_count GREATER 0)
    # Read the live normal variables here, after the project has made its
    # deliberate kernel32 removal.  The cache value is stale and is not link
    # authority.  Active-config additions are separately enumerated so they
    # cannot hide behind the base sequence.
    separate_arguments(
      _standard_library_base NATIVE_COMMAND
      "${CMAKE_CXX_STANDARD_LIBRARIES}")
    string(TOUPPER "${CMAKE_BUILD_TYPE}" _standard_library_config_upper)
    set(_standard_library_config_variable
        "CMAKE_CXX_STANDARD_LIBRARIES_${_standard_library_config_upper}")
    if(DEFINED ${_standard_library_config_variable})
      separate_arguments(
        _standard_library_config NATIVE_COMMAND
        "${${_standard_library_config_variable}}")
    else()
      set(_standard_library_config)
    endif()
    list(LENGTH _standard_library_base _standard_library_base_count)
    list(LENGTH _standard_library_config _standard_library_config_count)
    list(APPEND _standard_library_arguments
      --standard-library-configuration "${CMAKE_BUILD_TYPE}"
      --standard-library-base-count "${_standard_library_base_count}"
      --standard-library-config-count "${_standard_library_config_count}")
    foreach(_standard_library IN LISTS _standard_library_base)
      list(APPEND _standard_library_arguments
        --standard-library-base-item "${_standard_library}")
    endforeach()
    foreach(_standard_library IN LISTS _standard_library_config)
      list(APPEND _standard_library_arguments
        --standard-library-config-item "${_standard_library}")
    endforeach()
  endif()
  foreach(_launcher_variable
          CMAKE_C_COMPILER_LAUNCHER CMAKE_CXX_COMPILER_LAUNCHER)
    if(NOT "${${_launcher_variable}}" STREQUAL "${_guard_launcher}")
      message(FATAL_ERROR
        "${_launcher_variable} changed after byte-identity enablement")
    endif()
  endforeach()
  foreach(_build_directory IN LISTS _build_directories)
    get_property(_directory_rule_launcher DIRECTORY "${_build_directory}"
                 PROPERTY RULE_LAUNCH_COMPILE)
    if(_directory_rule_launcher)
      message(FATAL_ERROR
        "Directory RULE_LAUNCH_COMPILE hook is not permitted: ${_build_directory}")
    endif()
    get_property(_directory_link_launcher DIRECTORY "${_build_directory}"
                 PROPERTY RULE_LAUNCH_LINK)
    if(_directory_link_launcher)
      message(FATAL_ERROR
        "Directory RULE_LAUNCH_LINK hook is not permitted: ${_build_directory}")
    endif()
    # CMake language rules are directory-scoped variables.  Preserve the raw
    # list boundary and attest every discovered directory independently: a
    # semicolon-added second command or a locally rewritten rule must never be
    # made equivalent by flattening and shell-tokenizing it.
    foreach(_language C CXX)
      list(FIND _enabled_languages "${_language}" _language_index)
      if(_language_index LESS 0)
        continue()
      endif()
      get_directory_property(
        _raw_compile_rule DIRECTORY "${_build_directory}"
        DEFINITION CMAKE_${_language}_COMPILE_OBJECT)
      list(LENGTH _raw_compile_rule _raw_compile_rule_count)
      if(_language STREQUAL "CXX")
        # CMake 4.3.4's Windows-MSVC rule retains the empty
        # CMAKE_START_TEMP_FILE field between two literal spaces.  This is an
        # exact raw-template boundary: do not trim or normalize the spacing.
        set(_expected_raw_compile_rule
          "<CMAKE_CXX_COMPILER>  /nologo /TP <DEFINES> <INCLUDES> <FLAGS> /Fo<OBJECT> /Fd<OBJECT>.pdb -c <SOURCE>")
      else()
        set(_expected_raw_compile_rule
          "<CMAKE_C_COMPILER>  /nologo <DEFINES> <INCLUDES> <FLAGS> /Fo<OBJECT> /Fd<OBJECT>.pdb -c <SOURCE>")
      endif()
      if(NOT _raw_compile_rule_count EQUAL 1 OR
         NOT "${_raw_compile_rule}" STREQUAL "${_expected_raw_compile_rule}")
        message(FATAL_ERROR
          "${_language} COMPILE_OBJECT in ${_build_directory} must be one "
          "canonical raw command element; observed-count=${_raw_compile_rule_count} "
          "observed=[${_raw_compile_rule}]")
      endif()
    endforeach()
  endforeach()
  set(_discovered_compile_targets)
  set(_inventory_arguments)
  set(_input_inventory_arguments)
  set(_resource_targets)
  set(_resource_sources)
  set(_inventory_sources)
  foreach(_candidate_target IN LISTS _build_targets)
    get_target_property(_candidate_imported "${_candidate_target}" IMPORTED)
    get_target_property(_candidate_type "${_candidate_target}" TYPE)
    if(_candidate_imported)
      continue()
    endif()
    if(_candidate_type STREQUAL "OBJECT_LIBRARY")
      message(FATAL_ERROR
        "OBJECT_LIBRARY is an opaque linker-payload bypass in a byte-identity build: ${_candidate_target}")
    endif()
    get_target_property(_candidate_sources "${_candidate_target}" SOURCES)
    if(_candidate_sources MATCHES "-NOTFOUND$")
      set(_candidate_sources)
    endif()
    set(_candidate_has_compile_source FALSE)
    set(_candidate_source_ordinal 0)
    foreach(_candidate_source IN LISTS _candidate_sources)
      set(_candidate_current_ordinal "${_candidate_source_ordinal}")
      math(EXPR _candidate_source_ordinal "${_candidate_source_ordinal} + 1")
      if(_candidate_source MATCHES "\\$<")
        message(FATAL_ERROR
          "Generator-expression source on ${_candidate_target} is unsupported in a byte-identity build")
      endif()
      _isle_byte_identity_source_language(
        "${_candidate_target}" "${_candidate_source}"
        _candidate_source_abs _candidate_language)
      get_source_file_property(
        _candidate_external_object "${_candidate_source}"
        TARGET_DIRECTORY "${_candidate_target}" EXTERNAL_OBJECT)
      get_source_file_property(
        _candidate_external_object_abs "${_candidate_source_abs}"
        TARGET_DIRECTORY "${_candidate_target}" EXTERNAL_OBJECT)
      get_source_file_property(
        _candidate_generated "${_candidate_source}"
        TARGET_DIRECTORY "${_candidate_target}" GENERATED)
      get_source_file_property(
        _candidate_generated_abs "${_candidate_source_abs}"
        TARGET_DIRECTORY "${_candidate_target}" GENERATED)
      if(_candidate_external_object OR _candidate_external_object_abs)
        message(FATAL_ERROR
          "EXTERNAL_OBJECT source is forbidden in a byte-identity build: ${_candidate_target}:${_candidate_source_abs}")
      endif()
      _isle_byte_identity_source_overlay_authority(
        "${_candidate_source_abs}" _candidate_source_authority)
      if(_candidate_generated OR _candidate_generated_abs)
        _isle_byte_identity_overlay_generated_source_allowed(
          "${_candidate_target}" "${_candidate_source_abs}"
          "${_candidate_language}" "${_candidate_current_ordinal}"
          _overlay_generated_allowed)
        if(NOT _overlay_generated_allowed)
          message(FATAL_ERROR
            "Generated source/payload is forbidden in a byte-identity build: ${_candidate_target}:${_candidate_source_abs}")
        endif()
        if(NOT _candidate_source_authority STREQUAL "TYPED_SOURCE_OVERLAY")
          message(FATAL_ERROR
            "Generated source lacks typed overlay output authority: ${_candidate_source_abs}")
        endif()
      endif()
      get_filename_component(_candidate_suffix "${_candidate_source_abs}" LAST_EXT)
      string(TOLOWER "${_candidate_suffix}" _candidate_suffix_lower)
      if(_candidate_suffix_lower MATCHES "^\.(obj|o|lib|a|res|lo)$")
        message(FATAL_ERROR
          "Opaque object/archive/resource payload source is forbidden: ${_candidate_target}:${_candidate_source_abs}")
      endif()
      get_source_file_property(
        _candidate_header_only "${_candidate_source}"
        TARGET_DIRECTORY "${_candidate_target}" HEADER_FILE_ONLY)
      if(_candidate_header_only)
        if(NOT _candidate_suffix_lower MATCHES
           "^\.(h|hh|hpp|hxx|inc|inl)$")
          message(FATAL_ERROR
            "HEADER_FILE_ONLY source has an unsupported payload kind: ${_candidate_target}:${_candidate_source_abs}")
        endif()
        list(APPEND _input_inventory_arguments
          --input-entry "${_candidate_target}" "${_candidate_source_abs}" HEADER
          "${_candidate_current_ordinal}")
        continue()
      endif()
      if(_candidate_language AND
         NOT _candidate_language STREQUAL "C" AND
         NOT _candidate_language STREQUAL "CXX" AND
         NOT (_candidate_language STREQUAL "RC" AND
              _candidate_suffix_lower STREQUAL ".rc"))
        message(FATAL_ERROR
          "Unsupported effective source language ${_candidate_language} for "
          "${_candidate_target}:${_candidate_source_abs}")
      endif()
      if(NOT _candidate_language STREQUAL "C" AND
         NOT _candidate_language STREQUAL "CXX")
        if(_candidate_suffix_lower STREQUAL ".rc")
          list(APPEND _input_inventory_arguments
            --input-entry "${_candidate_target}" "${_candidate_source_abs}" RC
            "${_candidate_current_ordinal}")
          list(APPEND _resource_targets "${_candidate_target}")
          list(APPEND _resource_sources "${_candidate_source_abs}")
        elseif(_candidate_suffix_lower STREQUAL ".def")
          list(APPEND _input_inventory_arguments
            --input-entry "${_candidate_target}" "${_candidate_source_abs}" LINKER_DEF
            "${_candidate_current_ordinal}")
        else()
          message(FATAL_ERROR
            "Language-less or unsupported target source is forbidden in a byte-identity build: ${_candidate_target}:${_candidate_source_abs}")
        endif()
        continue()
      endif()
      set(_candidate_has_compile_source TRUE)
      if(ISLE_BYTE_IDENTITY_SOURCE_OVERLAY_ENABLED)
        list(APPEND _inventory_arguments
          --entry "${_candidate_target}" "${_candidate_source_abs}"
                  "${_candidate_language}" "${_candidate_current_ordinal}"
                  "${_candidate_source_authority}")
      else()
        list(APPEND _inventory_arguments
          --entry "${_candidate_target}" "${_candidate_source_abs}"
                  "${_candidate_language}" "${_candidate_current_ordinal}")
      endif()
      list(APPEND _inventory_sources "${_candidate_source_abs}")
      get_property(_source_rule_launcher_declared SOURCE "${_candidate_source}"
                   TARGET_DIRECTORY "${_candidate_target}"
                   PROPERTY RULE_LAUNCH_COMPILE)
      get_property(_source_rule_launcher_absolute SOURCE "${_candidate_source_abs}"
                   TARGET_DIRECTORY "${_candidate_target}"
                   PROPERTY RULE_LAUNCH_COMPILE)
      if(_source_rule_launcher_declared OR _source_rule_launcher_absolute)
        message(FATAL_ERROR
          "Source RULE_LAUNCH_COMPILE hook is not permitted: ${_candidate_source_abs}")
      endif()
    endforeach()
    if(NOT _candidate_has_compile_source)
      continue()
    endif()
    get_property(_target_rule_launcher TARGET "${_candidate_target}"
                 PROPERTY RULE_LAUNCH_COMPILE)
    if(_target_rule_launcher)
      message(FATAL_ERROR
        "Target RULE_LAUNCH_COMPILE hook is not permitted: ${_candidate_target}")
    endif()
    foreach(_launcher_property C_COMPILER_LAUNCHER CXX_COMPILER_LAUNCHER)
      get_property(_existing_launcher TARGET "${_candidate_target}"
                   PROPERTY "${_launcher_property}")
      if(_existing_launcher AND
         NOT "${_existing_launcher}" STREQUAL "${_guard_launcher}")
        message(FATAL_ERROR
          "Byte-identity target ${_candidate_target} already has ${_launcher_property}")
      endif()
    endforeach()
    list(APPEND _discovered_compile_targets "${_candidate_target}")
  endforeach()
  set(_declared_compile_targets ${ISLE_BYTE_IDENTITY_TARGETS})
  list(SORT _discovered_compile_targets)
  list(SORT _declared_compile_targets)
  if(NOT "${_discovered_compile_targets}" STREQUAL "${_declared_compile_targets}")
    message(FATAL_ERROR
      "Byte-identity target registry differs from build-system C/C++ targets; "
      "declared=[${_declared_compile_targets}] discovered=[${_discovered_compile_targets}]")
  endif()

  set(_inventory "${_state_dir}/inventory.json")
  set(_inventory_plan "${_state_dir}/inventory.cmake")
  set(_policy_stamp "${_state_dir}/policy.stamp")
  set(_command_inventory "${_state_dir}/command-inventory.json")
  set(_command_policy_stamp "${_state_dir}/command-policy.stamp")
  execute_process(
    COMMAND ${_python_command} "${_tool}" inventory
            --manifest "${_manifest}"
            --source-dir "${PROJECT_SOURCE_DIR}"
            --build-dir "${CMAKE_BINARY_DIR}"
            --compiler "${CMAKE_CXX_COMPILER}"
            --cmake-module "${_ISLE_BYTE_IDENTITY_MODULE}"
            --output "${_inventory}"
            --cmake-output "${_inventory_plan}"
            --policy-stamp "${_policy_stamp}"
            --emit-cmake
            ${_target_inventory_arguments}
            ${_graph_count_arguments}
            ${_graph_item_arguments}
            ${_standard_library_arguments}
            ${_input_inventory_arguments}
            ${_inventory_arguments}
    RESULT_VARIABLE _inventory_result
    OUTPUT_VARIABLE _inventory_output
    ERROR_VARIABLE _inventory_error
  )
  if(NOT _inventory_result EQUAL 0 OR
     NOT EXISTS "${_inventory}" OR
     NOT EXISTS "${_inventory_plan}" OR
     NOT EXISTS "${_policy_stamp}")
    message(FATAL_ERROR
      "Byte-identity TU inventory failed (${_inventory_result}):\n"
      "${_inventory_output}${_inventory_error}")
  endif()
  unset(ISLE_BYTE_IDENTITY_INVENTORY_COMPLETE)
  cmake_language(EVAL CODE "${_inventory_output}")
  if(NOT ISLE_BYTE_IDENTITY_INVENTORY_COMPLETE)
    message(FATAL_ERROR "Direct byte-identity inventory fragment is incomplete")
  endif()
  list(LENGTH _inventory_sources _inventory_source_count)
  list(LENGTH ISLE_BYTE_IDENTITY_INVENTORY_INDICES _inventory_plan_count)
  if(NOT _inventory_source_count EQUAL _inventory_plan_count)
    message(FATAL_ERROR "Byte-identity TU inventory count changed during configure")
  endif()
  list(REMOVE_DUPLICATES _inventory_sources)
  foreach(_inventory_target IN LISTS _discovered_compile_targets)
    get_target_property(_inventory_target_sources
                        "${_inventory_target}" SOURCES)
    set(_inventory_target_compile_sources)
    foreach(_inventory_target_source IN LISTS _inventory_target_sources)
      _isle_byte_identity_source_language(
        "${_inventory_target}" "${_inventory_target_source}"
        _inventory_target_source_abs _inventory_target_language)
      get_source_file_property(
        _inventory_header_only "${_inventory_target_source}"
        TARGET_DIRECTORY "${_inventory_target}" HEADER_FILE_ONLY)
      if(NOT _inventory_header_only AND
         (_inventory_target_language STREQUAL "C" OR
          _inventory_target_language STREQUAL "CXX"))
        list(APPEND _inventory_target_compile_sources
             "${_inventory_target_source}")
      endif()
    endforeach()
    set_property(
      SOURCE ${_inventory_target_compile_sources}
      TARGET_DIRECTORY "${_inventory_target}"
      APPEND PROPERTY OBJECT_DEPENDS
      "${ISLE_BYTE_IDENTITY_POLICY_STAMP}" "${_command_policy_stamp}")
  endforeach()

  # An earlier framework verdict must never survive a later failed rebuild.
  # This always-run dependency invalidates it before any affected target starts.
  add_custom_target(byte-identity-invalidate
    COMMAND ${_python_command} "${_tool}" invalidate
            --build-dir "${CMAKE_BINARY_DIR}"
    VERBATIM
  )

  # CMake writes compile_commands.json only after generation.  Authenticate
  # that generator-produced command universe at build start, before any object
  # may enter the compiler launcher.  The content stamp is also an object
  # prerequisite, so a definition/include/flag/order change forces recompiles.
  add_custom_target(byte-identity-attest-commands
    BYPRODUCTS "${_command_inventory}" "${_command_policy_stamp}"
    COMMAND ${_python_command} "${_tool}" attest-commands
            --manifest "${_manifest}"
            --source-dir "${PROJECT_SOURCE_DIR}"
            --build-dir "${CMAKE_BINARY_DIR}"
            --compiler "${CMAKE_CXX_COMPILER}"
            --compile-commands "${CMAKE_BINARY_DIR}/compile_commands.json"
            --output "${_command_inventory}"
            --policy-stamp "${_command_policy_stamp}"
    DEPENDS "${CMAKE_BINARY_DIR}/compile_commands.json" "${_inventory}"
            "${_policy_stamp}" "${_manifest}" "${_tool}"
    COMMENT "Attesting exact generated compiler argv and input roles"
    VERBATIM
  )
  add_dependencies(byte-identity-attest-commands byte-identity-invalidate)

  # Every pre-framework project target invalidates an earlier verdict when it
  # is built directly.  Verification waits for the complete recursive default
  # target set, so an unrelated late ALL target cannot fail after publication.
  foreach(_user_target IN LISTS _user_targets)
    add_dependencies("${_user_target}"
      byte-identity-invalidate byte-identity-attest-commands)
  endforeach()

  set(_affected_targets)
  foreach(_target IN LISTS ISLE_BYTE_IDENTITY_TARGETS)
    get_target_property(_target_link_options "${_target}" LINK_OPTIONS)
    if(_target_link_options)
      string(TOLOWER "${_target_link_options}" _target_link_options_lower)
      if(_target_link_options_lower MATCHES "(^|[ ;])[-/]debug([ :;]|$)")
        message(FATAL_ERROR
          "ISLE_BYTE_IDENTICAL target ${_target} still enables /debug")
      endif()
    endif()
    set(_launcher
      ${_python_command}
      "${_tool}"
      compile-launch
      --manifest "${_manifest}"
      --source-dir "${PROJECT_SOURCE_DIR}"
      --build-dir "${CMAKE_BINARY_DIR}"
      --target "${_target}"
      --configured-compiler "${CMAKE_CXX_COMPILER}"
      --
    )
    # CL handles both languages in this project. Pin both launcher properties
    # so a later .c source cannot silently bypass the same safety envelope.
    set_property(TARGET "${_target}" PROPERTY C_COMPILER_LAUNCHER ${_launcher})
    set_property(TARGET "${_target}" PROPERTY CXX_COMPILER_LAUNCHER ${_launcher})
    set_property(TARGET "${_target}" APPEND PROPERTY LINK_DEPENDS
      "${_manifest}" "${_tool}" "${_inventory}" "${_policy_stamp}")
    list(APPEND _affected_targets "${_target}")
  endforeach()

  # RC, LIB, and the terminal LINK are payload producers rather than C/C++
  # compiler invocations.  CMake has no list-valued launcher property for all
  # three on the supported generator floor, so quote every raw launcher token
  # for the POSIX host before assigning RULE_LAUNCH_* at the deferred tail.
  _isle_byte_identity_posix_quote("${Python3_EXECUTABLE}" _producer_python)
  _isle_byte_identity_posix_quote("${_tool}" _producer_tool)
  _isle_byte_identity_posix_quote("${_manifest}" _producer_manifest)
  _isle_byte_identity_posix_quote("${PROJECT_SOURCE_DIR}" _producer_source)
  _isle_byte_identity_posix_quote("${CMAKE_BINARY_DIR}" _producer_build)
  _isle_byte_identity_posix_quote("${CMAKE_CXX_COMPILER}" _producer_compiler)
  set(_producer_common
    "${_producer_python} -I -B ${_producer_tool}")

  # CMake's boolean grammar treats the string "0" as false.  Generated plan
  # indices are zero-based, so the sole production image is represented by
  # exactly that value; gate producer wiring on list structure, never value
  # truthiness.
  list(LENGTH ISLE_BYTE_IDENTITY_IMAGE_INDICES _image_count)
  list(LENGTH _resource_sources _resource_count)
  if(_resource_count GREATER 0 AND _image_count GREATER 0)
    set(_resource_dispatch_targets ${_resource_targets})
    list(REMOVE_DUPLICATES _resource_dispatch_targets)
    foreach(_resource_target IN LISTS _resource_dispatch_targets)
      _isle_byte_identity_posix_quote("${_resource_target}" _resource_target_q)
      set(_compile_dispatcher
        "${_producer_common} compile-dispatch --manifest ${_producer_manifest} --source-dir ${_producer_source} --build-dir ${_producer_build} --target ${_resource_target_q} --configured-compiler ${_producer_compiler} --")
      # RULE_LAUNCH_COMPILE is honored at target scope for RC as well as C/C++.
      # The dispatcher is outermost: it forwards the already-authenticated
      # compiler-launch chain unchanged and routes only an inventoried RC
      # command into resource-launch.
      set_property(TARGET "${_resource_target}" PROPERTY
                   RULE_LAUNCH_COMPILE "${_compile_dispatcher}")
    endforeach()
    math(EXPR _resource_last "${_resource_count} - 1")
    foreach(_resource_index RANGE 0 ${_resource_last})
      list(GET _resource_targets ${_resource_index} _resource_target)
      list(GET _resource_sources ${_resource_index} _resource_source)
      set_property(
        SOURCE "${_resource_source}"
        TARGET_DIRECTORY "${_resource_target}"
        APPEND PROPERTY OBJECT_DEPENDS
        "${_manifest}" "${_tool}" "${_inventory}"
        "${_policy_stamp}" "${_command_inventory}"
        "${_command_policy_stamp}")
    endforeach()
  endif()

  set(_first_party_archive_audits)
  if(_image_count GREATER 0)
    foreach(_producer_target IN LISTS _user_targets)
      get_target_property(_producer_type "${_producer_target}" TYPE)
      if(NOT _producer_type STREQUAL "STATIC_LIBRARY")
        continue()
      endif()
      _isle_byte_identity_posix_quote("${_producer_target}" _producer_target_q)
      set(_archive_launcher
        "${_producer_common} archive-launch --manifest ${_producer_manifest} --source-dir ${_producer_source} --build-dir ${_producer_build} --target ${_producer_target_q} --configured-compiler ${_producer_compiler} --")
      set_property(TARGET "${_producer_target}"
                   PROPERTY RULE_LAUNCH_LINK "${_archive_launcher}")
      list(APPEND _first_party_archive_audits
        "${_state_dir}/audit/first-party-archives/${_producer_target}.json")
    endforeach()
    # The release image stays free of /DEBUG.  The launcher derives a second
    # /DEBUG diagnostic invocation from these exact generated arguments and
    # proves identical linked .text before retaining its PDB for reccmp.
    target_link_options(lego1 PRIVATE
      "/MAP:${_state_dir}/final/LEGO1.map" "/VERBOSE:LIB")
    set(_terminal_link_launcher
      "${_producer_common} link-launch --manifest ${_producer_manifest} --source-dir ${_producer_source} --build-dir ${_producer_build} --target 'lego1' --identity 'LEGO1' --configured-compiler ${_producer_compiler} --")
    set_property(TARGET lego1 PROPERTY RULE_LAUNCH_LINK
                 "${_terminal_link_launcher}")
  endif()

  set(_listed_sources)
  foreach(_index IN LISTS ISLE_BYTE_IDENTITY_TU_INDICES)
    set(_prefix "ISLE_BYTE_IDENTITY_TU_${_index}")
    list(APPEND _listed_sources "${${_prefix}_SOURCE}")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
      "${${_prefix}_SOURCE}")
  endforeach()

  set(_materialized_outputs)
  # Recipe IDs are globally canonicalized by the native planner, so a shared
  # output/audit receives exactly one custom command even when several TUs use
  # the declaration shape.
  foreach(_recipe_id IN LISTS ISLE_BYTE_IDENTITY_RECIPE_IDS)
    set(_output_var "ISLE_BYTE_IDENTITY_RECIPE_${_recipe_id}_OUTPUT")
    set(_output "${${_output_var}}")
    if(NOT _output)
      message(FATAL_ERROR "Generated plan omitted output for recipe ${_recipe_id}")
    endif()
    add_custom_command(
      OUTPUT "${_output}"
      BYPRODUCTS
        "${_state_dir}/audit/materialization/${_recipe_id}.json"
      COMMAND ${_python_command} "${_tool}" materialize
              --manifest "${_manifest}"
              --source-dir "${PROJECT_SOURCE_DIR}"
              --build-dir "${CMAKE_BINARY_DIR}"
              --recipe-id "${_recipe_id}"
              --output "${_output}"
      DEPENDS "${_manifest}" "${_tool}" "${_entropy_tool}"
              "${_inventory}" "${_policy_stamp}" "${_command_inventory}"
              "${_command_policy_stamp}" ${_listed_sources}
      COMMENT "Materializing verified non-emitting declaration shape ${_recipe_id}"
      VERBATIM
    )
    list(APPEND _materialized_outputs "${_output}")
  endforeach()

  # SmartHeap and Smacker are the only user-authorized retail-payload
  # exceptions.  Copy each exact pinned archive into build authority, point
  # its imported target exclusively at that copy, and attest the declared
  # direct-link sequence at the true deferred tail before generation.
  foreach(_archive_index IN LISTS ISLE_BYTE_IDENTITY_ARCHIVE_INDICES)
    set(_archive_prefix "ISLE_BYTE_IDENTITY_ARCHIVE_${_archive_index}")
    set(_archive_identity "${${_archive_prefix}_IDENTITY}")
    set(_archive_target "${${_archive_prefix}_IMPORTED_TARGET}")
    set(_archive_source "${${_archive_prefix}_SOURCE}")
    set(_archive_output "${${_archive_prefix}_OUTPUT}")
    set(_archive_audit "${${_archive_prefix}_AUDIT}")
    if(NOT TARGET "${_archive_target}")
      message(FATAL_ERROR
        "Authorized archive target is absent: ${_archive_target}")
    endif()
    get_target_property(_archive_imported "${_archive_target}" IMPORTED)
    if(NOT _archive_imported)
      message(FATAL_ERROR
        "Authorized archive target is not imported: ${_archive_target}")
    endif()
    foreach(_contract_index IN LISTS ${_archive_prefix}_CONTRACT_INDICES)
      set(_contract_prefix
          "${_archive_prefix}_CONTRACT_${_contract_index}")
      _isle_attest_archive_link_sequence(
        "${${_contract_prefix}_TARGET}"
        "${${_contract_prefix}_OCCURRENCES}"
        ${${_contract_prefix}_SEQUENCE})
      set_property(
        TARGET "${${_contract_prefix}_TARGET}" APPEND PROPERTY LINK_DEPENDS
        "${_archive_output}" "${_archive_audit}")
    endforeach()
    set_property(
      TARGET "${_archive_target}" PROPERTY IMPORTED_LOCATION
      "${_archive_output}")
    add_custom_command(
      OUTPUT "${_archive_output}"
      BYPRODUCTS "${_archive_audit}"
      COMMAND ${_python_command} "${_tool}" materialize-archive
              --manifest "${_manifest}"
              --source-dir "${PROJECT_SOURCE_DIR}"
              --build-dir "${CMAKE_BINARY_DIR}"
              --identity "${_archive_identity}"
              --output "${_archive_output}"
      DEPENDS "${_archive_source}" "${_manifest}" "${_tool}"
              "${_inventory}" "${_policy_stamp}"
              "${_command_inventory}" "${_command_policy_stamp}"
      COMMENT
        "Materializing authorized exact ${_archive_identity} archive copy"
      VERBATIM
    )
    list(APPEND _materialized_outputs "${_archive_output}")
  endforeach()
  add_custom_target(byte-identity-materialize DEPENDS ${_materialized_outputs})
  add_dependencies(byte-identity-materialize
    byte-identity-invalidate byte-identity-attest-commands)
  # The generated-header OBJECT_DEPENDS edge is retained per listed TU, but
  # older Make generators do not reliably honor a custom-command output added
  # to an absolute source property after target creation. Make the build-wide
  # prerequisite explicit so no wrapped compile can observe an absent recipe.
  foreach(_target IN LISTS _affected_targets)
    add_dependencies("${_target}" byte-identity-materialize)
  endforeach()

  foreach(_index IN LISTS ISLE_BYTE_IDENTITY_TU_INDICES)
    set(_prefix "ISLE_BYTE_IDENTITY_TU_${_index}")
    set(_target "${${_prefix}_TARGET}")
    set(_source "${${_prefix}_SOURCE}")
    set(_outputs "${${_prefix}_OUTPUTS}")
    set(_audit "${${_prefix}_AUDIT}")
    if(NOT TARGET "${_target}")
      message(FATAL_ERROR "Byte-identity manifest references missing target: ${_target}")
    endif()
    get_target_property(_target_sources "${_target}" SOURCES)
    get_target_property(_target_source_dir "${_target}" SOURCE_DIR)
    set(_source_is_member FALSE)
    foreach(_candidate IN LISTS _target_sources)
      if(IS_ABSOLUTE "${_candidate}")
        get_filename_component(_candidate_abs "${_candidate}" REALPATH)
      else()
        get_filename_component(_candidate_abs "${_candidate}" REALPATH
                               BASE_DIR "${_target_source_dir}")
      endif()
      if("${_candidate_abs}" STREQUAL "${_source}")
        set(_source_is_member TRUE)
        break()
      endif()
    endforeach()
    if(NOT _source_is_member)
      message(FATAL_ERROR
        "Byte-identity source ${_source} is not a member of target ${_target}")
    endif()

    set_property(SOURCE "${_source}" TARGET_DIRECTORY "${_target}"
      APPEND PROPERTY OBJECT_DEPENDS
      "${_manifest}" "${_tool}" "${_entropy_tool}" ${_outputs})
    set_property(SOURCE "${_source}" TARGET_DIRECTORY "${_target}"
      APPEND PROPERTY OBJECT_OUTPUTS
      "${_audit}")
  endforeach()
  list(REMOVE_DUPLICATES _affected_targets)
  foreach(_affected_target IN LISTS _affected_targets)
    if(NOT _affected_target IN_LIST _default_user_targets)
      message(FATAL_ERROR
        "Excluded C/C++ target is unsupported by the build-wide verification universe: "
        "${_affected_target}")
    endif()
  endforeach()

  add_custom_target(byte-identity-verify
    ALL
    COMMAND ${_python_command} "${_tool}" verify
            --manifest "${_manifest}"
            --source-dir "${PROJECT_SOURCE_DIR}"
            --build-dir "${CMAKE_BINARY_DIR}"
            --compiler "${CMAKE_CXX_COMPILER}"
            --no-publish
    DEPENDS "${_inventory}" "${_policy_stamp}"
            "${_command_inventory}" "${_command_policy_stamp}"
    COMMENT "Reconstructing compiler-output COMDAT audits (final gates remain fail-closed)"
    VERBATIM
  )
  # Target names in add_custom_target(DEPENDS) are generator-dependent file
  # dependencies.  Express build ordering as target graph edges explicitly.
  add_dependencies(byte-identity-verify
    byte-identity-materialize ${_default_user_targets})
  if(_image_count GREATER 0)
    if(NOT _image_count EQUAL 1)
      message(FATAL_ERROR
        "The final byte-identity contract currently requires exactly LEGO1")
    endif()
    list(GET ISLE_BYTE_IDENTITY_IMAGE_INDICES 0 _image_index)
    set(_image_prefix "ISLE_BYTE_IDENTITY_IMAGE_${_image_index}")
    if(NOT "${${_image_prefix}_IDENTITY}" STREQUAL "LEGO1"
       OR NOT "${${_image_prefix}_TARGET}" STREQUAL "lego1"
       OR NOT TARGET lego1)
      message(FATAL_ERROR "The final LEGO1 image plan differs")
    endif()
    # This is deliberately explicit rather than ALL.  Iteration builds retain
    # the incomplete object/archive verdict; release completion additionally
    # requires a freshly generated fixed-seat reccmp JSON report and proves
    # 4933/4933 plus byte-for-byte SHA-256/MD5 image identity.
    add_custom_target(byte-identity-reccmp
      BYPRODUCTS
        "${_state_dir}/final/LEGO1.json"
        "${_state_dir}/final/LEGO1-reccmp.log"
        "${_state_dir}/audit/reccmp/LEGO1.json"
      COMMAND ${_python_command} "${_tool}" reccmp-launch
              --manifest "${_manifest}"
              --source-dir "${PROJECT_SOURCE_DIR}"
              --build-dir "${CMAKE_BINARY_DIR}"
              --identity LEGO1
              --configured-compiler "${CMAKE_CXX_COMPILER}"
      COMMENT "Producing nonce-bound reccmp report from authenticated LINK outputs"
      VERBATIM
    )
    add_dependencies(byte-identity-reccmp byte-identity-verify)
    add_custom_target(byte-identity-complete
      COMMAND "${CMAKE_COMMAND}" -E true
      COMMENT "Deferring terminal verdict publication to the resident outer driver"
      VERBATIM
    )
    add_dependencies(byte-identity-complete byte-identity-reccmp)
    set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_CLEAN_FILES
      "${_state_dir}/audit/resources"
      "${_state_dir}/audit/first-party-archives"
      "${_state_dir}/audit/links"
      "${_state_dir}/audit/reccmp"
      "${_state_dir}/final"
      "${CMAKE_BINARY_DIR}/LEGO1.pdb"
      "${CMAKE_BINARY_DIR}/LEGO1.exp")
  endif()
  message(STATUS
    "ISLE_BYTE_IDENTICAL manifest framework enabled (${ISLE_BYTE_IDENTITY_PHASE}); "
    "strict compiler-output FPO composition enabled; explicit final image gate configured")
endfunction()
