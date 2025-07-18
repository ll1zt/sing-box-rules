# Sing-box 分类规则集 (自动更新)

这是一个自动生成和更新 [Sing-box](https://sing-box.sagernet.org/) 分类规则集（Rule Set）的项目。它每日自动从 [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) 仓库拉取最新规则，并将其转换为 Sing-box 可用的二进制格式（`.srs` 文件），然后按照分类进行归档和合并。


## 📦 规则分类

目前生成的规则集包含以下主要分类：

- 📵 `Advertising` (去广告)
- 🌏 `Global` (全球服务)
- 🌏 `GlobalMedia` (全球媒体)
- 🇨🇳 `Mainland` (中国大陆)
- 🇨🇳 `MainlandMedia` (中国大陆媒体)
- 📺 `Media` (综合媒体)
- 🎮 `Game` (游戏)
- 🍎 `Apple` (苹果服务)
- 🗄️ `Microsoft` (微软服务)
- 📟 `Google` (谷歌服务)
- 🚫 `Reject` (拒绝访问)
- 🖥️ `Other` (其他)

## 感谢

- **[blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)**: 提供了核心的 Clash 规则源。
- **[MaxMind GeoLite2 ASN Database](https://www.maxmind.com/)**: 提供了 IP 地址到 ASN 的映射数据。
- **[Sing-box](https://sing-box.sagernet.org/)**: 强大的网络代理工具及其规则集编译功能。

