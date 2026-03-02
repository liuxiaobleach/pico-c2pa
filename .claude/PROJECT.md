# brevis-c2pa-verifier 项目记忆

## 项目概述

这是一个基于 **Pico ZKVM** 的 **C2PA（Coalition for Content Provenance and Authenticity）图片签名验证零知识证明项目**。

- **目的**: 实现隐私保护的 C2PA 图片签名验证（通过零知识证明）
- **语言**: Rust 2024 edition (nightly)
- **核心框架**: Pico ZKVM, c2pa-rust

## 项目结构

```
/Users/liuxiao/code/tour/Fibonacci/
├── Cargo.toml                  # Workspace 配置
├── rust-toolchain              # nightly-2025-08-04
├── README.md                   # 项目文档
├── verifier/                   # 主机 C2PA 验证工具
│   ├── Cargo.toml
│   ├── src/main.rs
│   ├── src/verifier_test.rs
│   └── src/DSC00050.JPG        # 测试图片
├── app-c2pa/                   # Pico ZKVM 应用
│   ├── Cargo.toml
│   ├── src/main.rs
│   └── elf/riscv32im-pico-zkvm-elf  # 编译后的 ELF
├── prover-c2pa/                # ZK Proof 生成器
│   ├── Cargo.toml
│   └── src/main.rs
└── openspec/                   # OpenSpec 配置
```

## 核心模块

### 1. verifier (主机验证工具)
- 直接验证图片的 C2PA 签名
- 支持文件输入和 base64 输入
- 使用 `c2pa-rust` 库 (v0.76)
- 支持格式: JPEG, PNG, WebP, GIF, AVIF

### 2. app-c2pa (Pico ZKVM 应用)
- 运行在 RISC-V 架构 (riscv32im-pico-zkvm-elf)
- 执行简化的 C2PA 哈希验证
- 输入: image_hash, expected_hash, image_size, is_signed
- 输出: computed_hash, hash_valid, public values

### 3. prover-c2pa (ZK Proof 生成器)
- 加载 app-c2pa 的 ELF
- 在 Pico ZKVM 上执行 app-c2pa
- 生成零知识证明并验证 public values

## 常用命令

```bash
# 构建所有包
cargo build

# 运行 verifier (直接验证)
cargo run -p verifier -- --file <图片路径>
cargo run -p verifier -- --file ./verifier/src/DSC00050.JPG --verbose

# 构建 Pico ZKVM app
cd app-c2pa && cargo pico build

# 运行 prover (ZK 验证)
cargo run -p prover-c2pa

# 运行测试
cargo test -p verifier
```

## 依赖项

- **c2pa-rust**: v0.76 - C2PA 签名验证
- **pico-sdk**: v1.3.0 - Pico ZKVM SDK
- **clap**: v4.5 - CLI 参数解析
- **serde**: v1.0.205 - 序列化
- **log, env_logger**: 日志

## 输出示例

### verifier 成功输出
```
=== C2PA Verification Results ===

✓ Verification Status: PASSED

--- Manifest Info ---
✓ C2PA Manifest: Found
  Label: urn:uuid:4d7c9981-d887-4005-829a-033422a7e865
  Claim Generator: SONY_CAMERA
  Title: DSC00050.JPG
```

### prover-c2pa 输出
```
Input: image_hash=1311768467294899695, expected_hash=1311768467294899695, size=150000, is_signed=true

Public values: C2paResult {
    hash_valid: false,
    computed_hash: 17407...,
    image_hash: 13117...,
    expected_hash: 13117...,
    image_size: 150000,
    is_signed: true
}

Verification PASSED!
```

## 环境要求

- Rust nightly-2025-08-04
- cargo-pico 工具链
- Pico SDK

## 注意事项

1. 没有 C2PA manifest 的图片会显示 PASSED 但有警告
2. 完整签名验证需要信任锚点文件
3. ZK 方式保护了图片数据的隐私，只公开验证结果
