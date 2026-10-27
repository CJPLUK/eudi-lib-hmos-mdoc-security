# eudi_lib_mdoc_security

EU Digital Identity Wallet 的 **ISO/IEC 18013-5 §9 安全层**(仓颉 / HarmonyOS),移植自欧盟委员会官方参考实现 [eudi-lib-ios-iso18013-security](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-security)。

> scope:x509certificates 子目录已独立为 [eudi_lib_x509](https://github.com/CJPLUK/eudi-lib-hmos-x509) 模块,本库消费它、不重做。

## 功能(5 领域)

| 子包 | 能力 |
|---|---|
| **session** | 会话加密:ECDH 临时密钥协商(P-256/HUKS)+ HKDF 派生(SKDevice/SKReader)+ AES-256-GCM 加解密(nonce 角色/方向计数);SessionTranscript/Establishment/Data CBOR |
| **secure_area** | SecureArea 实现:SoftwareSecureArea(core-crypto 软件密钥)+ HuksSecureArea(HUKS 硬件密钥);createKey/sign/keyAgreement |
| **issuer_auth** | MSO 验证:ValueDigests digest 对账 + ValidityInfo + 签发方证书链(x509)|
| **device_auth** | 设备认证:DeviceAuthentication COSE_Sign1 / COSE_Mac0(EMacKey 派生);detached COSE |
| **reader_auth** | 读取方认证:ReaderAuthentication COSE_Sign1 验证 + reader 证书链(x509)|

## 仓库结构(团队统一 cbor 形态)

```
eudi_lib_mdoc_security/
├── eudi_cjmdoc_security/          ← HAR 模块(pkg ohos_app_cangjie_eudi_cjmdoc_security)
│   └── src/main/cangjie/security/ ← session / secure_area / issuer_auth / device_auth / reader_auth
├── entry/                         ← 测试面板 HAP(44 个设备 E2E + "Run mDoc-Security Demo")
│   └── libs/{stdx, arm64-v8a}/    ← stdx 1.1.3.1 + OpenSSL/libsecurec 运行时件
└── third_party/                   ← (gitignored)上游锁定 clone,见下
```

## 上游依赖(首次构建前 — 扁平 third_party,含二级传递)

本库依赖 mdoc-data-model / core-crypto / x509,**且 mdoc-data-model 又依赖 cbor + core-crypto**(二级传递)。解法:third_party **平铺全闭包**,并改写 mdoc-data-model clone 的相对路径上跳一层(详见团队 lib-packaging-spec §9):

```bash
cd third_party
git clone https://github.com/CJPLUK/eudi-lib-hmos-mdoc-data-model && (cd eudi_lib_mdoc_data_model && git checkout v0.1.0)
git clone https://github.com/CJPLUK/eudi-lib-hmos-core-crypto       && (cd eudi_lib_core_crypto && git checkout v0.1.0)
git clone https://github.com/CJPLUK/eudi-lib-hmos-x509        && (cd eudi_lib_x509 && git checkout v0.1.0)
git clone https://github.com/CJPLUK/eudi-lib-hmos-cbor        && (cd eudi_lib_cbor && git checkout v0.1.0)
# mdoc-data-model 的 cjpm.toml 相对路径上跳到扁平层:
sed -i '' 's|\.\./third_party/|../../|g' eudi_lib_mdoc_data_model/eudi_cjmdoc_data_model/cjpm.toml
```

## 下游消费(cjpm path 依赖)

```toml
[dependencies]
  [dependencies.ohos_app_cangjie_eudi_cjmdoc_security]
    path = "../third_party/eudi_lib_mdoc_security/eudi_cjmdoc_security"
```

```cangjie
import ohos_app_cangjie_eudi_cjmdoc_security.security.session.*
import ohos_app_cangjie_eudi_cjmdoc_security.security.issuer_auth.*
```

## 构建与验证

构建命令、环境变量、运行时件要求同团队 lib-packaging-spec,参照 [eudi_lib_sdjwt](https://github.com/CJPLUK/eudi-lib-hmos-sdjwt) README 的"构建"一节。

- **44 个设备端 E2E**(`entry/.../unittest_engine.cj`,OpenHarmonyTestRunner):session HKDF/AES-GCM/CBOR、**ECDH 真机(HUKS 硬件协商,设备实证)**、secure_area Software/HUKS、issuer/device/reader auth、demo、UI 冒烟
- 测试面板:app 内点 **Run mDoc-Security Demo** → `OK: ...`(会话加密+MSO验证+设备认证三链)

## ⚠ ECDH 真机说明

会话加密的 ECDH 协商走 core-crypto 的 `EcdhP256.agree`(HUKS 别名制硬件密钥)。本模块是该路径的首个真机消费者,设备 E2E `SessionEcdhHuksE2EUT` 已实证:HUKS 上 ECDH 协商出 32 字节共享密钥、双向对称、喂入 HKDF 派生会话密钥成功。

## License

[Apache License 2.0](LICENSE)。本项目为 eudi-lib-ios-iso18013-security(© European Commission)的衍生移植,归属与捆绑件声明见 [NOTICE](NOTICE)。
