# 陶修夷程序分享 🐱‍👤 Ultimate Research Edition

> **一个 Windows 底层 / 安全机制 / 对抗技术研究合集。**
> 包含若干用于学习 Windows 内核机制、权限管理、持久化、反调试、防御绕过与系统行为分析的实验性程序。
>
> ⚠️ **本仓库包含极度危险的代码，请务必完整阅读 README 后再决定是否编译或运行。**

---

# ⚠️ 超重要警告（请认真看）

本仓库中的部分程序具备：

* 文件批量加密
* 系统关键区域破坏
* 注册表持久化
* 计划任务持久化
* 关键进程保护
* UAC 绕过
* 自复制
* 反调试 / 反虚拟机
* 蓝屏触发（BSOD）
* 引导扇区覆盖（MBR/GPT）
* SYSTEM 权限运行

等高风险行为。

一旦运行错误：

* 你的系统可能无法启动
* 文件可能永久损坏
* 虚拟机可能直接报废
* 真机数据可能无法恢复

---

# ❌ 严禁在以下环境运行

* 主力电脑
* 工作电脑
* 学校电脑
* 存有重要文件的设备
* 未备份数据的设备
* 不懂 Windows 恢复流程的环境

---

# ✅ 推荐运行环境

* VMware / VirtualBox 虚拟机
* Hyper-V 隔离环境
* 已创建快照的测试系统
* 无重要数据的物理测试机

---

# 📌 免责声明

本项目：

* 仅用于安全研究
* 仅用于 Windows 底层机制学习
* 仅用于防御与逆向分析研究

严禁：

* 非法传播
* 攻击他人设备
* 未授权测试
* 任何违法用途

使用本仓库代码造成的一切后果：

* 数据丢失
* 系统损坏
* 法律责任
* 社会性死亡
* 被朋友追杀

均与作者无关。

你运行它的那一刻，默认你已经理解全部风险。

---

# 📦 仓库内容

| 文件 / 目录            | 说明                 | 风险等级  |
| ------------------ | ------------------ | ----- |
| `DadChallenge.cpp` | Windows 安全研究程序核心源码 | 🔴 极高 |
| `不要打开的东西/`         | 一些实验性整活程序          | 🔴 高危 |
| `提瓦特幸存者单独一个游戏本体/`  | 幸存者类小游戏            | 🟢 安全 |
| `提瓦特幸存者安装包/`       | 游戏安装包              | 🟢 安全 |

---

# 🔬 DadChallenge.cpp 技术研究内容

当前版本：

> **Win7 / Win10 / Win11 全兼容研究版**

涵盖了大量 Windows 底层机制与对抗技术。

---

# 🧠 功能模块总览

| 模块   | 内容                         |
| ---- | -------------------------- |
| 权限提升 | UAC 绕过（Win7 / Win10+ 自动适配） |
| 进程保护 | Critical Process + 安全描述符   |
| 守护机制 | 双进程心跳守护                    |
| 持久化  | 注册表 + 计划任务                 |
| 对抗分析 | 反调试 / 反虚拟机 / 反沙箱           |
| 加密模块 | 多线程 AES-256-CBC            |
| 系统破坏 | MBR/GPT 覆盖                 |
| 进程伪装 | 修改 PEB 伪装为 svchost         |
| 蓝屏模块 | NtRaiseHardError           |
| 沙箱规避 | 随机延迟 + 硬件检测                |
| 自删除  | 自复制 + 删除源文件                |

---

# 🧩 核心技术细节

## 1️⃣ UAC 绕过（系统版本自适应）

### Win10 / Win11

使用：

* `fodhelper.exe`
* `ms-settings`
* DelegateExecute 劫持

实现无提示提权。

---

### Win7

使用：

* `eventvwr.exe`
* `mscfile`
* 注册表劫持

兼容老系统。

---

# 2️⃣ 关键进程保护

程序会调用：

* `RtlSetProcessIsCritical`

将自身设置为：

> “关键系统进程”

强行结束：

* 任务管理器
* Process Hacker
* taskkill

都有概率直接蓝屏。

---

# 3️⃣ 严格安全描述符

使用：

```text
D:P(A;;GA;;;SY)(A;;GXGR;;;BA)
```

实现：

* SYSTEM 完全控制
* 管理员只能读取/执行
* 无法终止进程

---

# 4️⃣ 双进程守护机制

主进程与守护进程：

* 相互监控
* 心跳同步
* 自动检测异常退出

若主进程失联：

* 自动触发加密
* 覆盖引导扇区
* 蓝屏

---

# 5️⃣ AES-256 文件加密

使用：

* Windows BCrypt API
* AES-256-CBC
* 随机 Key
* 随机 IV
* PKCS7 Padding

特点：

* 多线程加密
* 固定驱动器遍历
* 自动过滤扩展名
* 跳过系统目录

---

## 已支持的目标文件类型

包括但不限于：

```text
doc/docx
xls/xlsx
ppt/pptx
pdf/txt/csv
jpg/png/jpeg
cpp/h/py/js
zip/rar/7z
mp3/mp4/mkv
```

---

# 6️⃣ 引导扇区破坏

直接写入：

```text
\\.\PhysicalDrive0
```

覆盖：

* MBR
* GPT 备份区域

效果：

> 系统无法启动。

---

# 7️⃣ 反调试 / 反虚拟机

当前版本检测：

| 检测项        | 内容                |
| ---------- | ----------------- |
| Debug API  | IsDebuggerPresent |
| PEB        | BeingDebugged     |
| Hypervisor | CPUID             |
| CPU核心数     | 小于2核判定异常          |
| 内存大小       | 小于2GB判定异常         |
| 磁盘容量       | 小于40GB判定异常        |
| VirtualBox | ACPI注册表检测         |
| VMware     | ACPI注册表检测         |

---

# 8️⃣ 进程伪装

直接修改：

* PEB
* RTL_USER_PROCESS_PARAMETERS

将自身伪装为：

```text
C:\Windows\System32\svchost.exe
```

任务管理器中更难发现。

---

# 9️⃣ 持久化机制

包含：

## 注册表自启动

```text
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

---

## 计划任务

任务名：

```text
WindowsUpdateService
```

支持：

* Win7
* Win10
* Win11

---

# 🔟 自复制与隐藏

程序会：

* 复制到 System32
* 设置：

  * Hidden
  * System

属性。

随后：

* 删除原始文件

---

# 🧪 编译指南

## 开发环境

推荐：

* Visual Studio 2019
* Visual Studio 2022

必须安装：

```text
使用 C++ 的桌面开发
```

---

# 📦 编译命令

打开：

```text
Developer PowerShell for VS
```

执行：

```powershell
cl DadChallenge.cpp /Fe:DadChallenge.exe /link ^
bcrypt.lib ^
taskschd.lib ^
comsuppw.lib ^
advapi32.lib ^
shell32.lib ^
shlwapi.lib ^
iphlpapi.lib ^
psapi.lib
```

---

# ▶️ 运行方式

## 普通模式

```powershell
DadChallenge.exe
```

---

## 静默模式

```powershell
DadChallenge.exe /silent
```

---

## 守护模式（内部使用）

```powershell
DadChallenge.exe /guard PID
```

---

# 🎮 交互模式说明

程序会给予：

> 3 次机会输入 “爸爸”

输入正确：

* 清理持久化
* 删除计划任务
* 恢复安全状态
* 正常退出

输入错误：

* 文件加密
* 引导区破坏
* 打开遗书
* 系统蓝屏

---

# 🧼 清理机制

挑战成功后：

* 删除计划任务
* 删除注册表启动项
* 删除复制文件
* 删除状态记录

---

# ⚙️ 当前兼容性

| 系统         | 支持情况 |
| ---------- | ---- |
| Windows 7  | ✅    |
| Windows 8  | ✅    |
| Windows 10 | ✅    |
| Windows 11 | ✅    |

---

# 📚 适合学习的方向

本项目适合研究：

* Windows 内核机制
* 权限管理
* 安全描述符
* UAC 机制
* 进程保护
* PE / PEB
* 反调试
* 对抗技术
* Windows API
* 持久化机制
* 沙箱检测
* BCrypt 加密接口
* Windows Task Scheduler COM

---

# ⚠️ 再次强调

这不是：

* 玩具程序
* 普通整蛊软件
* 安全小实验

当前版本已经包含：

> 真正具备系统破坏能力的危险逻辑。

请不要在真机运行。

真的不要。

---

# 📜 License

MIT License

你可以：

* 学习
* 修改
* Fork
* 研究

但必须保留原作者声明。

---

# 🤝 欢迎交流

如果你也喜欢：

* Windows 底层
* 系统机制
* 安全研究
* 逆向工程
* 对抗技术

欢迎：

* Fork
* PR
* Issue
* 一起整活

---

# 🧨 最后的警告

如果你不知道：

* 什么是快照
* 怎么恢复 MBR
* 怎么修系统
* 什么是 PE/PEB
* 什么是 SYSTEM 权限

那你最好不要运行它。

真的。
