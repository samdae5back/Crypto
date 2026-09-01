add_executable(liberacrypt_key_agreement_unit UnitTest.c)
target_link_libraries(liberacrypt_key_agreement_unit PRIVATE LiberaCrypt)
set_target_properties(liberacrypt_key_agreement_unit PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
liberac_configure_portable_warnings(liberacrypt_key_agreement_unit)
add_test(NAME LiberaCrypt.KeyAgreement.Unit
    COMMAND liberacrypt_key_agreement_unit)
set_tests_properties(LiberaCrypt.KeyAgreement.Unit PROPERTIES
    LABELS "unit;key-agreement;ecdh;x25519")
