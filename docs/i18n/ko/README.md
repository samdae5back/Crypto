# LiberaCrypt 문서

LiberaCrypt의 저장소 `README.md`는 프로젝트의 성격과 사용 시작점을 빠르게 파악할 수 있도록 의도적으로 간결하게 유지합니다. 자세한 사용법, 설계 근거, 보안 주의사항, 최적화 기록, 벤치마크 해석은 별도의 문서에서 다룹니다.

## 시작하기

- [LiberaCrypt 빌드](../../getting-started/building.md)
- [LiberaCrypt 통합](../../getting-started/integration.md)
- [API 개요](../../api/overview.md)
- [알고리즘 선택](../../api/algorithm-selection.md)
- [알고리즘 계열](../../algorithms/overview.md)

## 설계

- [아키텍처](../../design/architecture.md)
- [이식성](../../design/portability.md)
- [Constant-time 정책](../../design/constant-time.md)

이 문서들은 표준 알고리즘의 수학적 정의보다 LiberaCrypt가 구현을 어떤 원칙으로 구성하는지를 설명합니다. 특히 이식성과 timing 특성은 단순한 부가 기능이 아니라 명시적으로 검토해야 하는 구현 속성으로 취급합니다.

## 보안

- [보안 고려사항](../../security/security-considerations.md)
- [레거시 및 호환성 알고리즘](../../security/legacy-algorithms.md)

알고리즘을 선택하거나 저수준 primitive를 직접 사용하기 전에 이 문서들을 확인하는 것을 권장합니다.

## 알고리즘

- [알고리즘 계열 개요](../../algorithms/overview.md)
- [키 유도](../../key-derivation.md)

함수 시그니처, 인자, 반환값, 공개 선언의 기준은 생성되는 Doxygen API reference입니다. Markdown 문서는 각 구성 요소를 어떤 방식으로 함께 사용하도록 설계했는지를 설명합니다.

## 최적화와 벤치마크

- [최적화 문서 인덱스](../../optimization/README.md)
- [Bignum 최적화](../../optimization/Bignum.md)
- [ECC 최적화](../../optimization/ECC.md)
- [Ed25519 최적화](../../optimization/Ed25519.md)
- [ML-KEM 최적화](../../optimization/ML-KEM.md)
- [ML-KEM Barrett/Montgomery 실험](../../optimization/ML-KEM-Barrett.md)
- [RSA 최적화](../../optimization/RSA.md)
- [벤치마크 구성](../../benchmarks/README.md)

최적화 문서는 기준 구현, 변경 내용, 검증 조건, 그리고 최종 구현을 선택한 이유를 기록합니다. 실제 벤치마크 프로그램은 저장소 최상위의 `benchmarks/` 디렉터리에 둡니다.

## 개발

- [테스트와 검증](../../development/testing.md)

서드파티 코드의 출처와 라이선스 정보는 저장소 최상위의 `THIRD_PARTY_NOTICES.md`에 기록합니다.
