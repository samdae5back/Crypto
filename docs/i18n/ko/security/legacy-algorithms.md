# 레거시 및 호환성 알고리즘

LiberaCrypt에는 기존 시스템과의 상호운용성, 과거 표준의 테스트 벡터 재현, primitive 수준 테스트를 주목적으로 하는 여러 primitive가 포함되어 있습니다.

라이브러리에 포함되어 있다는 사실이 새로운 프로토콜 설계에서 해당 알고리즘을 선택하라는 권고를 의미하지는 않습니다.

## SHA-1

SHA-1은 여전히 이를 요구하는 프로토콜과 데이터 형식과의 호환성을 위해 제공됩니다. 외부 사양이 SHA-1을 요구하지 않는 한 새로운 보안 설계에서는 더 강한 hash family를 사용해야 합니다.

## Triple-DES / TDEA

3-key Triple-DES EDE는 block-cipher API와 legacy CTR_DRBG option에서 사용할 수 있습니다. 이 selector들은 interoperability와 standards-era validation을 위해 존재합니다. 새로운 설계는 일반적으로 modern AES 또는 적절한 authenticated-encryption construction을 사용해야 합니다.

2-key TDEA와 single DES는 block-cipher dispatcher에서 제공하지 않습니다.

## ECB

ECB mode는 primitive/block-mode interface 및 compatibility/testing을 위해 유지됩니다. 반복되는 block pattern을 숨기지 못하므로 general-purpose secure message-encryption mode로 취급해서는 안 됩니다.

## Raw RSA

raw textbook RSA 연산은 primitive test와 호환성을 위해 남아 있습니다. application-level RSA 암호화에는 RSAES-OAEP를 사용하고, 서명에는 RSASSA-PSS 또는 프로토콜이 요구하는 다른 표준 scheme을 사용해야 합니다.

## 호환성 정책

legacy support는 API와 documentation 계층 모두에서 명확히 표시되어야 합니다. 레거시 알고리즘을 유지하는 경우:

- 호환성 목적을 명시해야 합니다.
- 현대적인 대안을 쉽게 찾을 수 있어야 합니다.
- 레거시 파라미터가 관계없는 modern API에 강제로 섞이지 않아야 합니다.
- validation을 통해 compatibility code가 다른 algorithm family의 동작을 약화시키지 않는지 확인해야 합니다.
