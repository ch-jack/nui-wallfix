# nui-wallfix

一个面向 FiveM NUI resource 的纯命令行外网静态资源扫描、国内 CDN 替换和本地化工具。

第一版保持 Python 3.7 标准库兼容，不需要安装 pip 依赖，也不会修改 `ck_free_toolbox`。以后工具箱可以通过稳定的 JSON 输出或 `nuiwallfix.api` 调用同一套核心逻辑。

## 安全默认值

- `scan` 永远不联网、不写文件。
- `apply` 默认只是联网解析和生成预览；只有显式提供 `--write` 才会写入。
- `fetch`、WebSocket、远程 iframe、FiveM NUI callback 等业务地址只报告，不自动替换。
- 国内 CDN 文件默认必须和原文件逐字节一致，或者通过页面现有 SRI；不能证明等价时保持原文件不变。
- 本地化会递归处理 CSS 的 `@import`/`url()` 以及 ES module、Worker 的静态依赖。
- 下载默认拒绝回环、内网、链路本地及保留地址，防止扫描不可信 resource 时产生 SSRF。
- 每次实际写入都在目标目录之外备份；中途失败自动回滚。
- restore 检测 apply 之后的用户改动，默认拒绝覆盖冲突。

## 快速使用

在 PowerShell 或 CMD 中：

```powershell
cd D:\fivem\nui-wallfix

# 只扫描，不联网、不修改
.\nui-wallfix.cmd scan "D:\server\resources"

# 解析 auto 方案，但仍然不写入
.\nui-wallfix.cmd apply "D:\server\resources" --mode auto

# 确认预览后实际写入
.\nui-wallfix.cmd apply "D:\server\resources" --mode auto --write

# 使用 apply 输出的 run id 回滚
.\nui-wallfix.cmd restore "D:\server\resources" --run-id 20260710-123456-abcdef
```

也可以直接运行：

```powershell
python -u D:\fivem\nui-wallfix\nui-wallfix.py scan "D:\server\resources" --json
python -u -m nuiwallfix scan "D:\server\resources"
```

使用 `python -m nuiwallfix` 时，当前目录需要是 `D:\fivem\nui-wallfix`，或者该目录已经加入 `PYTHONPATH`。

## 每次执行报告

每次 `scan`、`apply` 预览、`apply --write` 和 `restore` 结束时都会自动生成一份独立执行报告。报告不是备份恢复日志，也不会被下一次执行覆盖。

默认目录：

```text
<target-parent>/.nui-wallfix-reports/YYYY/MM/DD/<execution-id>/
  report.json
  report.md
```

根目录同时维护各操作的最新快捷副本：`latest-scan.*`、`latest-preview.*`、`latest-apply.*`、`latest-restore.*`。可以用 `--report-dir PATH` 把报告集中到工具箱目录，但该目录必须位于目标 resource 树之外。

四种报告分别记录不同内容：

- 扫描：resource、外链位置与类型、自动候选、仅报告原因和诊断；明确本次不联网、不改文件。
- 预览：每条引用的 remote/local/unresolved/report-only 决策、计划文件和验证方式；明确没有写入和备份。
- 写入：实际改写文件的前后 SHA-256、备份、Run ID、journal 和恢复能力。
- 恢复：关联 Apply Run ID、恢复文件、冲突、是否强制以及恢复后的 journal 状态。

输入错误、文件写入错误、恢复冲突和可捕获的中断也会尝试生成失败报告。持久报告会移除 URL 用户信息和 fragment，并把 query 值替换为 `<redacted>`；`--json` 返回的原生 URL 不变。JSON 结果中的 `execution_report` 提供本次历史报告和 latest 文件路径。

## 三种模式

### `auto`（推荐）

先尝试配置中的国内 CDN。候选文件通过 SRI 或与原文件 SHA256 内容一致性验证后，保留为远程国内链接；没有安全映射时下载到 NUI 的 `_vendor` 目录。

### `local`

直接下载到当前 resource 的 `<ui-root>/_vendor/`，并把引用改为相对路径。CSS 和 JavaScript 的静态子依赖也会递归下载，适合希望 NUI 不再依赖外部网络的场景。

### `cn-cdn`

只允许替换为 `providers.json` 中的国内 CDN。不支持映射或校验失败的引用保持不变。

如果原站不可访问、页面没有 SRI、工具也无法证明镜像字节一致，可以显式加：

```powershell
--allow-unverified-mirror
```

这个参数表示信任 `providers.json` 中的精确路径映射，安全性低于默认模式，不建议批量盲用。

## 可识别内容

- HTML：`script[src]`、stylesheet/preload/modulepreload `link[href]`
- HTML：图片、字体预加载、媒体静态地址、`srcset`
- HTML：内联 `<style>`、内联 module script、`style` 属性
- CSS：`@import`、`url(...)`
- JavaScript：静态 `import`、`export ... from`、`import()`
- JavaScript：`Worker`、`SharedWorker`、`importScripts`、静态 `new URL(...)`

以下内容不会自动修改：

- 普通字符串或注释中的 URL
- 动态模板和动态拼接 URL
- `fetch`、WebSocket、EventSource 等业务请求
- FiveM NUI callback
- 远程 `ui_page`、iframe 页面

报告会保留文件、行列、类型、处理动作以及未处理原因。

## JSON 与工具箱接口

`--json` 保证 stdout 只输出一个 JSON 结果：

```powershell
.\nui-wallfix.cmd scan "D:\server\resources" --json
.\nui-wallfix.cmd apply "D:\server\resources" --mode local --json
```

也可以写入指定文件：

```powershell
.\nui-wallfix.cmd scan "D:\server\resources" --json --json-output "D:\temp\wallfix-report.json"
```

Python 调用入口：

```python
from nuiwallfix.api import scan, apply, restore

report = scan(r"D:\server\resources")
preview = apply(r"D:\server\resources", mode="auto", write=False)
```

CLI 不使用 `input()` 或其他交互确认，适合以后由工具箱子进程调用。

## 固定退出码

| 退出码 | 含义 |
| ---: | --- |
| `0` | 命令成功 |
| `10` | apply 成功完成预览/写入，但存在 unresolved 或 report-only 项，需要人工检查 |
| `20` | 参数、目标、配置、解析或安全检查错误 |
| `40` | 文件系统写入错误 |
| `50` | restore 检测到 apply 后的文件冲突 |

扫描发现外链本身不是错误，因此正常 `scan` 返回 `0`。

## 备份和恢复

默认备份目录位于目标目录的同级：

```text
<target-parent>/.nui-wallfix-backups/runs/<run-id>/
```

它不会放进 resource 内部，避免被 FiveM 的 `files '**/*'` 打包或加载。可以使用 `--state-dir` 指定其他目标外目录。

如果 local 模式生成的 `_vendor` 文件没有被 manifest 当前的 `files` 覆盖，工具会追加一个带注释的最小 `files` 块。restore 会恢复 manifest、HTML/CSS/JS，并删除本次新增的 vendor 文件。

## 国内 CDN 配置

默认配置是项目根目录的 `providers.json`。第一版包含：

- cdnjs 路径到 BootCDN 的精确前缀候选
- 带明确版本和文件路径的 jsDelivr npm/unpkg URL 到 npmmirror 文件端点候选

所有候选仍需在运行时校验；配置存在不代表一定会替换。可以复制并编辑配置，再通过 `--providers` 指定：

```json
{
  "schema_version": 1,
  "rules": [
    {
      "name": "my-exact-mirror",
      "type": "prefix",
      "source": "https://foreign.example/assets/",
      "target": "https://cn.example/assets/"
    }
  ]
}
```

## 其他参数

```text
--timeout SECONDS              单次网络请求超时，默认 15 秒
--max-bytes BYTES              单个下载最大尺寸，默认 20 MiB
--allow-private-network        允许下载回环/内网地址，仅适用于可信测试环境
--allow-unverified-mirror      显式信任无法证明字节一致的镜像映射
--state-dir PATH               指定目标目录之外的备份目录
```

## 当前限制

- JavaScript 使用保守的静态词法识别，不执行代码，也不会猜测动态 URL。
- 只处理 NUI 实际页面目录中的 HTML/CSS/JS 构建产物，不替代 npm/Vite/Webpack 的源码构建流程。
- `cn-cdn` 模式验证入口文件，但不会下载并改写远程 CSS/JS 内部依赖；需要完全离线时使用 `local`。
- 国内镜像可用性会变化，实际结果以每次运行的网络校验报告为准。
- 工具不能替代 FiveM 客户端中的最终 NUI 冒烟测试；正式部署前仍应检查浏览器控制台和 resource 启动日志。

## 测试

```powershell
cd D:\fivem\nui-wallfix
python -m unittest discover -s tests -v
```

测试使用临时 FiveM resource 和本机临时 HTTP server，不会修改现有资源。
