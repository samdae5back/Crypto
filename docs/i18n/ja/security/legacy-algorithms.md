# レガシーおよび互換性アルゴリズム

LiberaCrypt には、既存システムとの相互運用、過去の標準の test vector 再現、primitive レベルのテストを主目的とする複数の primitive が含まれています。

ライブラリに含まれていること自体は、新しいプロトコル設計でそれらを選択する推奨を意味しません。

## SHA-1

SHA-1 は依然としてそれを要求するプロトコルやデータ形式との互換性のために利用できます。外部仕様が SHA-1 を要求しない限り、新しいセキュリティ設計ではより強い hash family を使用してください。

## Triple-DES / TDEA

3-key Triple-DES EDE は block-cipher API と legacy CTR_DRBG option で利用できます。これらの selector は interoperability と standards-era validation のために存在します。新しい設計では通常、modern AES または適切な authenticated-encryption construction を使用してください。

2-key TDEA と single DES は block-cipher dispatcher では公開されません。

## ECB

ECB mode は primitive/block-mode interface および compatibility/testing のために保持されています。繰り返し block pattern を隠さないため、general-purpose secure message-encryption mode として扱ってはいけません。

## Raw RSA

raw textbook RSA operation は primitive test と互換性のために残されています。application-level RSA encryption には RSAES-OAEP、署名には RSASSA-PSS またはプロトコルで要求される別の標準 scheme を使用してください。

## 互換性ポリシー

legacy support は API と documentation の両方で明確に表示されるべきです。legacy algorithm を保持する場合:

- 互換性の目的を明示すること;
- modern alternative を容易に見つけられること;
- legacy parameter を無関係な modern API に押し込まないこと;
- validation により compatibility code が他の algorithm family の動作を弱めないことを確認すること。
