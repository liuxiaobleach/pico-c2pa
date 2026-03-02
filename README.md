# brevis-c2pa-verifier

基于 Pico ZKVM 的 C2PA 图片签名验证零知识证明项目。

## 项目简介

本项目实现了一个基于零知识证明的 C2PA（Coalition for Content Provenance and Authenticity）图片签名验证系统。

### 什么是 C2PA？

C2PA 是一个开放标准，用于记录和验证数字内容的来源和真实性。它允许：

- **来源追踪**：确定图片的创建者/设备
- **完整性验证**：检测图片是否被篡改
- **真实性证明**：验证内容是否由声称的来源创建

### 什么是零知识证明？

零知识证明（ZKP）允许一方（证明者）向另一方（验证者）证明某个陈述是真实的，而无需透露任何额外信息。

在本项目中：
- **Private（私密）**：原始图片数据
- **Public（公开）**：验证结果

这样可以在不暴露图片内容的情况下，证明"这张图片的 C2PA 签名验证结果"。

## 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                      brevis-c2pa-verifier                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    │
│  │    verifier   │    │   app-c2pa   │    │ prover-c2pa  │    │
│  │  (主机工具)   │    │ (Pico ZKVM)  │    │  (生成 Proof) │    │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘    │
│         │                    │                    │              │
│         ▼                    ▼                    ▼              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │  C2PA 签名   │    │  ELF 二进制  │    │  ZK Proof   │      │
│  │  验证工具    │    │  (RISC-V)    │    │  + Public   │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│                                                                  │
│  方式一                    方式二（ZK 隐私保护）                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 模块说明

| 模块 | 说明 |
|------|------|
| `verifier` | 主机上的 C2PA 验证工具，可直接验证图片的 C2PA 签名 |
| `app-c2pa` | 运行在 Pico ZKVM 上的 C2PA 验证应用 |
| `prover-c2pa` | 生成 ZK Proof，验证 app-c2pa 的执行结果 |

## 环境要求

- Rust 2024 edition
- Pico SDK (通过 `cargo pico` 工具链)
- Nightly Rust 工具链

## 快速开始

### 1. 安装 Pico 工具链

```bash
cargo install cargo-pico
```

### 2. 克隆项目

```bash
git clone <你的仓库URL>
cd brevis-c2pa-verifier
```

### 3. 构建项目

```bash
# 构建所有包
cargo build
```

## 使用方法

### 方式一：使用 verifier（主机工具）

直接验证图片的 C2PA 签名，无需零知识证明。

```bash
# 从文件验证
cargo run -p verifier -- --file <图片路径>

# 示例
cargo run -p verifier -- --file ./verifier/src/DSC00050.JPG

# 详细输出（显示完整 JSON）
cargo run -p verifier -- --file <图片路径> --verbose

# 从 base64 验证
cargo run -p verifier -- --base64 "<base64字符串>"
```

### 方式二：使用 Pico ZKVM + Prover（零知识证明）

通过零知识证明验证 C2PA 签名，保护隐私。

#### 步骤 1: 编译 app-c2pa

```bash
cd app-c2pa
cargo pico build
```

这会生成 ELF 文件：`app-c2pa/elf/riscv32im-pico-zkvm-elf`

#### 步骤 2: 运行 prover 生成 Proof

```bash
cargo run -p prover-c2pa
```

这会在 Pico ZKVM 上执行 app-c2pa 并生成零知识证明。

## 命令参考

### verifier 命令

```bash
cargo run -p verifier -- [OPTIONS]

Options:
  -f, --file <FILE>           图片文件路径
      --base64 <BASE64>       Base64 编码的图片数据
  -s, --settings <FILE>       信任设置文件（可选）
  -t, --trust-anchors <FILE>  信任锚点 PEM 文件（可选）
  -v, --verbose               详细输出模式
  -h, --help                  帮助信息
```

### app-c2pa 编译

```bash
cd app-c2pa
cargo pico build

# 指定输出目录
cargo pico build --output-directory <目录>
```

### prover-c2pa 运行

```bash
cargo run -p prover-c2pa
```

## 输出示例

### verifier 输出（有 C2PA 签名）

```
=== C2PA Verification Results ===

✓ Verification Status: PASSED

--- Manifest Info ---
✓ C2PA Manifest: Found
  Label: urn:uuid:4d7c9981-d887-4005-829a-033422a7e865
  Claim Generator: SONY_CAMERA
  Title: DSC00050.JPG

================================
```

### verifier --verbose 输出（完整 JSON）

```json
{
  "active_manifest": "urn:uuid:4d7c9981-d887-4005-829a-033422a7e865",
  "manifests": {
    "urn:uuid:4d7c9981-d887-4005-829a-033422a7e865": {
      "claim_generator": "SONY_CAMERA",
      "title": "DSC00050.JPG",
      "format": "image/jpeg",
      "signature_info": {
        "alg": "Es256",
        "time": "2026-03-02T02:22:47+00:00"
      }
    }
  },
  "validation_state": "Valid"
}
```

### prover-c2pa 输出

```
Input: image_hash=1311768467294899695, expected_hash=1311768467294899695, size=150000, is_signed=true
[DEBUG] postprocess: accessed_addrs len: 14758

Public values: C2paResult {
    hash_valid: false,
    computed_hash: 17407...,
    image_hash: 13117...,
    expected_hash: 13117...,
    image_size: 150000,
    is_signed: true
}

hash_valid: false (computed in ZKVM)
Verification PASSED!
```

## C2PA Manifest 详解

当 verifier 成功验证一张图片时，会显示以下信息：

| 字段 | 说明 |
|------|------|
| **Label** | Manifest 的唯一标识符（UUID） |
| **Claim Generator** | 创建此 manifest 的软件/设备（如 SONY_CAMERA） |
| **Title** | 文件名 |
| **format** | 图片格式（image/jpeg） |

### 验证状态

| 状态 | 说明 |
|------|------|
| ✅ timeStamp.validated | 时间戳验证通过 |
| ✅ timeStamp.trusted | 时间戳证书受信任 |
| ✅ claimSignature.validated | 声明签名有效 |
| ✅ assertion.dataHash.match | 数据哈希匹配 |

## Public Value 说明

**Public Value（公开值）** 是在 ZKVM 中执行程序后，向外部公开的部分证明数据。

### 在本项目中的意义

```
┌─────────────────────────────────────────────┐
│              ZKVM 执行 (app-c2pa)            │
│                                             │
│  输入 (Private - 不公开):                    │
│    - image_hash                             │
│    - expected_hash                          │
│    - image_size                             │
│    - is_signed                              │
│                                             │
│  输出 (Public Values - 公开):               │
│    ✓ hash_valid                             │
│    ✓ computed_hash                          │
│    ✓ image_hash                             │
│    ✓ expected_hash                          │
│    ✓ image_size                             │
│    ✓ is_signed                              │
└─────────────────────────────────────────────┘
```

### 特点

1. **公开可见** - 任何人都可以看到这些值
2. **可验证** - 无需知道原始输入就能验证计算正确性
3. **隐私保护** - 原始输入（图片数据）在 ZKVM 内部保持私密

## 项目结构

```
brevis-c2pa-verifier/
├── Cargo.toml              # Workspace 配置
├── app/                   # 原来的 Fibonacci app
├── app-c2pa/              # C2PA 验证 app (Pico ZKVM)
│   ├── Cargo.toml
│   ├── src/main.rs
│   └── elf/               # 编译生成的 ELF
├── lib/                   # 公共库
├── prover/                # 原来的 Fibonacci prover
├── prover-c2pa/           # C2PA prover
│   ├── Cargo.toml
│   └── src/main.rs
├── verifier/              # C2PA 验证工具
│   ├── Cargo.toml
│   ├── README.md
│   └── src/
│       ├── main.rs
│       └── verifier_test.rs
└── openspec/              # OpenSpec 配置
```

## 运行测试

```bash
# 运行 verifier 测试
cargo test -p verifier
```

## 注意事项

1. 没有 C2PA manifest 的图片会被标记为 "PASSED" 但会显示警告
2. 完整的签名验证需要提供信任锚点文件
3. 支持的图片格式：JPEG, PNG, WebP, GIF, AVIF

## 相关链接

- [C2PA 官方网站](https://c2pa.org/)
- [Pico SDK 文档](https://docs.brevis.network/)
- [C2PA Rust SDK](https://github.com/contentauth/c2pa-rust)
- [Pico ZKVM 快速开始](https://pico-docs.brevis.network/getting-started/quick-start)

## 许可证

MIT License
