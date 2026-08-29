add_executable(crypto_message_authentication_unit UnitTest.c)
target_link_libraries(crypto_message_authentication_unit PRIVATE LiberaCrypt)
set_target_properties(crypto_message_authentication_unit PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
liberac_configure_portable_warnings(crypto_message_authentication_unit)
add_test(NAME LiberaCrypt.MessageAuthentication.Unit
    COMMAND crypto_message_authentication_unit)
set_tests_properties(LiberaCrypt.MessageAuthentication.Unit PROPERTIES
    LABELS "unit;message-authentication")

add_executable(crypto_message_authentication_kat KAT.c)
target_link_libraries(crypto_message_authentication_kat PRIVATE LiberaCrypt)
set_target_properties(crypto_message_authentication_kat PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
liberac_configure_portable_warnings(crypto_message_authentication_kat)
add_test(NAME LiberaCrypt.MessageAuthentication.KAT
    COMMAND crypto_message_authentication_kat)
set_tests_properties(LiberaCrypt.MessageAuthentication.KAT PROPERTIES
    LABELS "kat;message-authentication")
