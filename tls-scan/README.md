# tls-scan

内网 TLS 配置体检工具:对指定 host:port 主动握手探测,按可配置基线打分。纯 Node + TypeScript,零运行时依赖。

## 探测能力

| 检查项 | 实现方式 |
|---|---|
| 协议版本 (TLS1.0–1.3) | 逐版本 `minVersion=maxVersion` 钉死握手 |
| 每个版本的套件列表 | 消除法枚举:提供全部候选 → 记录服务端选中项 → 移除 → 重复,每版本只需 (支持数+1) 次连接 |
| TLS 1.3 套件 | Node API 无法限定 1.3 套件,自动回退用 `openssl s_client -ciphersuites` 消除法枚举;CLI 不可用时只报告实际协商到的套件 |
| 服务端套件顺序 | 同一对套件按两种顺序各握一次,选中结果不变 ⇒ 服务端坚持自己的顺序 |
| 安全重协商 (RFC 5746) | 裸 socket 发手工构造的 ClientHello,解析 ServerHello 是否带 `renegotiation_info` 扩展;另发起一次真实的客户端主动重协商看服务端是否接受 |
| OCSP 装订 | 握手时带 `status_request`,监听 `OCSPResponse` 事件 |
| HSTS | TLS 上发 HTTP/1.1 GET,解析 `Strict-Transport-Security`(max-age / includeSubDomains / preload);非 HTTP 服务标记 n/a |
| 证书 |  subject/issuer/有效期/自签,供基线扣分 |

## 使用

```bash
npm install
npm run build

# 单个/多个目标
node dist/cli.js --host 10.0.1.5:443 --host 10.0.1.6:8443

# 目标清单文件(每行 host:port 或 host port,# 为注释)
node dist/cli.js --targets targets.txt

# 自定义基线(与内置默认深合并,只需写要改的字段)
node dist/cli.js --targets targets.txt --baseline baseline.example.json

# CI 门禁:有任何主机低于 B 就 exit 1
node dist/cli.js --targets targets.txt --fail-below B --json report.json
```

常用参数:`--concurrency`(全局并发连接数,默认 8)、`--hosts-concurrency`(并行主机数,默认 3)、`--timeout`(单连接超时,默认 5000ms)、`--no-tls13-enum`、`--no-hsts`、`--verbose`、`--no-color`。

## 本地测试环境

```bash
sh test-servers/gen-certs.sh   # 生成迷你 CA、CA 签发的证书、真实 OCSP 响应、自签证书
npm run servers                # 起三个配置各异的服务
npm run demo                   # 扫这三个服务
```

| 端口 | 画像 | 预期评级 |
|---|---|---|
| 9443 modern | TLS1.2+1.3、强 PFS 套件、服务端套件顺序、OCSP 装订、长 HSTS、CA 签发证书 | A |
| 9444 legacy | TLS1.0–1.2、非 PFS 套件、客户端决定套件顺序、无 HSTS、无 OCSP、自签 | F |
| 9445 mixed | TLS1.1–1.2、强弱套件混杂、短 max-age HSTS | D |

## 打分

从 100 分扣起,权重全部可在基线 JSON 里调(`weights` 节),等级:A≥90 / B≥75 / C≥60 / D≥45 / F<45。扣分项:禁用协议、弱套件(可配模式,带扣分上限)、非前向保密套件、服务端不坚持套件顺序、缺安全重协商信号、允许客户端主动重协商、缺 OCSP 装订、HSTS 缺失/max-age 过短、证书过期/将到期/自签。完整字段见 `src/baseline.ts` 的 `DEFAULT_BASELINE` 和 `baseline.example.json`。

## 并发与"别把服务探挂"

- 全局信号量限制同时在飞的连接数(默认 8),所有主机共享;
- 套件枚举用消除法而不是逐套件试,连接数从 ~50/版本 降到 (支持数+1)/版本;
- 单连接 5s 超时,所有 socket 用完即销毁;
- 每个主机约 30–60 次短连接,对正常服务无感。

## 已知限制

- **弱套件覆盖受客户端 OpenSSL 制约**:本机 Node 内置 OpenSSL 3.6 已把 RC4/DES/3DES/MD5/NULL/EXPORT 移出默认提供者,客户端根本发不出这些套件,也就探不到服务端的对应支持。"未发现弱套件"的准确含义是"客户端能提供的套件里没有弱套件"。需要完整弱套件覆盖时,用系统 openssl(或静态编译带 legacy provider 的 OpenSSL)扩展 `probeCiphers.ts` 的候选列表。
- **不安全重协商(legacy renegotiation,CVE-2009-3555)无法从现代 OpenSSL 客户端触发**,工具报告的是 RFC 5746 安全重协商的支持情况;`renegotiation_info` 缺失会扣分并提示。
- TLS 1.3 套件枚举依赖系统 `openssl` CLI(≥1.1.1);没有时退化为只报协商到的套件。
- HSTS 探测发的是 HTTP/1.1;纯 HTTP/2-only 或非 HTTP 服务会标记为 n/a。
