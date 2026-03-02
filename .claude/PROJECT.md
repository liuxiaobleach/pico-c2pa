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
│   └── src/DSC00050.JPG        # 测试图片（索尼相机拍摄）
├── app-c2pa/                   # Pico ZKVM 应用
│   ├── Cargo.toml
│   ├── src/main.rs
│   └── elf/riscv32im-pico-zkvm-elf  # 编译后的 ELF
├── prover-c2pa/                # ZK Proof 生成器
│   ├── Cargo.toml
│   └── src/main.rs
├── cropper/                    # C2PA 图片裁剪工具
│   ├── Cargo.toml
│   ├── src/main.rs
│   └── sigcert.p12            # 设备证书（如果有）
└── openspec/                   # OpenSpec 配置
```

## 核心模块

### 1. verifier (主机验证工具)
- 直接验证图片的 C2PA 签名
- 支持文件输入和 base64 输入
- 使用 `c2pa-rust` 库 (v0.76)
- 支持格式: JPEG, PNG, WebP, GIF, AVIF
- **新功能**: `--history` 显示修改历史, `--skip-trust` 跳过证书信任验证

### 2. app-c2pa (Pico ZKVM 应用)
- 运行在 RISC-V 架构 (riscv32im-pico-zkvm-elf)
- 执行简化的 C2PA 哈希验证
- 输入: image_hash, expected_hash, image_size, is_signed
- 输出: computed_hash, hash_valid, public values

### 3. prover-c2pa (ZK Proof 生成器)
- 加载 app-c2pa 的 ELF
- 在 Pico ZKVM 上执行 app-c2pa
- 生成零知识证明并验证 public values

### 4. cropper (图片裁剪工具)
- 验证原始图片的 C2PA 签名
- 裁剪图片
- 创建新的 C2PA manifest 记录裁剪操作

## 常用命令

```bash
# 构建所有包
cargo build

# 运行 verifier (直接验证)
cargo run -p verifier -- --file <图片路径>
cargo run -p verifier -- --file ./verifier/src/DSC00050.JPG --skip-trust

# 显示修改历史
cargo run -p verifier -- --file <图片路径> --skip-trust --history

# 构建 Pico ZKVM app
cd app-c2pa && cargo pico build

# 运行 prover (ZK 验证)
cargo run -p prover-c2pa

# 运行 cropper (裁剪图片)
cd cropper && cargo build
./target/debug/cropper --input <原图> --output <输出> --width 1000 --height 1000

# 运行测试
cargo test -p verifier
```

## verifier 输出说明

### 验证检查 (Validation Checks)

| 验证项 | 状态 | 说明 |
|--------|------|------|
| `timeStamp.validated` | ✅ | 时间戳消息摘要匹配 |
| `timeStamp.trusted` | ✅ | 时间戳证书受信任 |
| `claimSignature.validated` | ✅ | 声明签名有效 |
| `claimSignature.insideValidity` | ✅ | 签名在有效期内 |
| `assertion.dataHash.match` | ✅ | **图片内容没有被修改** |
| `signingCredential.untrusted` | ⚠️ | 签名证书不在信任列表中 |

### 修改历史 (Modification History)

```
--- Modification History (3 steps) ---
  [Step 1] c2pa.created           # 相机创建
           Software: SONY_CAMERA

  [Step 2] c2pa.opened            # 打开图片

  [Step 3] c2pa.cropped           # 裁剪操作
           Params: width: 1000, height: 1000, x: 0, y: 0
```

### 重要说明

**为什么可以忽略 `signingCredential.untrusted`？**

- 这是两个独立的验证：
  1. **签名有效** = 用私钥签名，能用公钥解开
  2. **证书信任** = 证书是否在 Adobe AATL 信任列表中

- 即使不知道签名者是否可信（证书不受信任），仍可通过以下验证保证图片真实性：
  - `assertion.dataHash.match` = 图片内容没被修改 ✅
  - `claimSignature.validated` = 签名有效 ✅

## 依赖项

- **c2pa-rust**: v0.76 - C2PA 签名验证
- **pico-sdk**: v1.3.0 - Pico ZKVM SDK
- **clap**: v4.5 - CLI 参数解析
- **serde**: v1.0.205 - 序列化
- **log, env_logger**: 日志
- **image**: v0.25 - 图片处理 (cropper 使用)

## 环境要求

- Rust nightly-2025-08-04
- cargo-pico 工具链
- Pico SDK

## 注意事项

1. 使用 `--skip-trust` 可以跳过证书信任验证，避免 `signingCredential.untrusted` 警告
2. 没有 C2PA manifest 的图片会显示 PASSED 但有警告
3. 完整签名验证需要信任锚点文件
4. ZK 方式保护了图片数据的隐私，只公开验证结果
