include_guard(GLOBAL)
set(_ISLE_BYTE_IDENTITY_MODULE "${CMAKE_CURRENT_LIST_FILE}")

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
