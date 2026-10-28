---
name: web-audit
description: Web 漏洞验证与取证：注入/越权/文件读取的最小可复现验证
license: MIT
---

# Web 漏洞验证

## 原则
**先证明，再上报。** 没有可复现请求与响应的结论，一律不登记为 finding。

## 验证套路

### SQL 注入
```bash
# 布尔盲注最小验证：比较真/假条件的响应差异
curl -sS "http://<target>/search?q=1'%20AND%201=1--%20" -o /tmp/a
curl -sS "http://<target>/search?q=1'%20AND%201=2--%20" -o /tmp/b
cmp -s /tmp/a /tmp/b && echo "无差异（疑似未注入）" || echo "响应不同，需进一步确认"
```

### 越权（IDOR）
```bash
# 用账号 A 的凭据请求账号 B 的资源 id
curl -sS -H "Authorization: Bearer <A-token>" "http://<target>/api/orders/<B-id>"
```

### 任意文件读取
```bash
curl -sS "http://<target>/download?file=../../../../etc/passwd" | head -3
```

## 登记 finding 的必要条件
- [ ] 原始请求 + 原始响应（进证据链，哈希可校验）
- [ ] 说明影响（能读到什么、能改到什么）
- [ ] 给出修复建议
- [ ] 标注 ATT&CK 技术（`argus` 会自动映射）

## 禁止
- 拖库、批量导出真实用户数据（验证到"能读一行"即止）
- 写入 webshell、修改配置
- 对生产库执行 `DROP`/`UPDATE`
