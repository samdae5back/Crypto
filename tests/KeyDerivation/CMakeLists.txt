add_executable(crypto_key_derivation_unit UnitTest.c)
target_link_libraries(crypto_key_derivation_unit PRIVATE LiberaCrypt)
set_target_properties(crypto_key_derivation_unit PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
liberac_configure_portable_warnings(crypto_key_derivation_unit)
add_test(NAME LiberaCrypt.KeyDerivation.Unit
    COMMAND crypto_key_derivation_unit)
set_tests_properties(LiberaCrypt.KeyDerivation.Unit PROPERTIES
    LABELS "unit;key-derivation")

add_executable(crypto_key_derivation_kat KAT.c)
target_link_libraries(crypto_key_derivation_kat PRIVATE LiberaCrypt)
set_target_properties(crypto_key_derivation_kat PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
liberac_configure_portable_warnings(crypto_key_derivation_kat)
add_test(NAME LiberaCrypt.KeyDerivation.KAT
    COMMAND crypto_key_derivation_kat)
set_tests_properties(LiberaCrypt.KeyDerivation.KAT PROPERTIES
    LABELS "kat;key-derivation")
