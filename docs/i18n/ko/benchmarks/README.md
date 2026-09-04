# 벤치마크

LiberaCrypt에서 벤치마크 소스 코드와 벤치마크 결과의 해석은 서로 다른 역할을 가집니다.

## 저장소 구성

```text
benchmarks/          벤치마크 프로그램과 fixture
docs/benchmarks/     벤치마크 구성 및 결과 읽기 가이드
docs/optimization/   컴포넌트별 측정 결과와 구현 선택 기록
```

저장소 최상위의 `benchmarks/` 디렉터리에는 현재 Bignum과 ECC에 초점을 맞춘 벤치마크 프로그램이 있습니다. 알고리즘별 결과 표와 그 결과에서 도출한 판단은 메인 README에 복사하기보다 해당 optimization 문서와 함께 보관해야 합니다.

## 보고 정책

벤치마크 기록에는 비교가 의미 있도록 충분한 문맥을 포함해야 합니다.

- 비교한 revision 또는 구현 단계;
- 연산과 파라미터 세트;
- compiler/toolchain 및 관련 build configuration;
- 운영체제 또는 hosted runner;
- 반복/집계 방법;
- 값이 절대 throughput/latency인지 상대 percentage change인지;
- 비교가 same-host, hosted-runner, cross-library 중 무엇인지.

한 플랫폼에서 측정한 결과를 알고리즘의 보편적인 성질처럼 제시해서는 안 됩니다.

## 부정적인 결과도 중요하다

최적화 실험이 더 느렸더라도 유용한 engineering result가 될 수 있습니다. ML-KEM Montgomery 실험을 보존하는 이유가 이것입니다. portable 기본 구현이 왜 Montgomery가 아니라 Barrett reduction을 유지했는지, 기각된 대안을 문서화하지 않은 채 남겨두지 않고 설명할 수 있습니다.

## 결과를 둘 위치

- Bignum 결과: [Bignum 최적화](../../optimization/Bignum.md)
- ECC 결과: [ECC 최적화](../../optimization/ECC.md)
- ML-KEM 결과: [ML-KEM 최적화](../../optimization/ML-KEM.md) 및 [ML-KEM Barrett 실험](../../optimization/ML-KEM-Barrett.md)
- RSA 결과/결정: [RSA 최적화](../../optimization/RSA.md)
- Ed25519 결과/결정: [Ed25519 최적화](../../optimization/Ed25519.md)

최상위 README에는 최적화 작업이 문서화되고 측정된다는 사실만 요약해야 합니다. 자세한 표는 이 문서 계층 또는 컴포넌트별 optimization note에 둡니다.
