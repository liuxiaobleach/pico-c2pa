# C2PA Signature Verification Tool

C2PA 图片签名验证工具，用于验证图片的 C2PA（Coalition for Content Provenance and Authenticity）签名。

## 功能特性

- 支持从文件或 base64 输入验证图片
- 自动检测图片格式（JPEG, PNG, WebP, GIF, AVIF）
- 显示 C2PA manifest 信息
- 列出图片的 ingredients
- 支持完整的签名验证（需要信任锚点）

## 构建

```bash
# 构建项目
cargo build -p verifier
```

## 使用方法

### 1. 从文件验证

```bash
cargo run -p verifier -- --file <图片路径>
```

示例：

```bash
cargo run -p verifier -- --file ./src/DSC00050.JPG
```

### 2. 从 base64 验证

```bash
# 将图片转为 base64
base64 <图片路径> | tr -d '\n'

# 使用 base64 数据验证
cargo run -p verifier -- --base64 "<base64字符串>"
```

### 3. 详细输出模式

添加 `-v` 或 `--verbose` 参数查看完整的 JSON manifest 信息：

```bash
cargo run -p verifier -- --file <图片路径> --verbose
```

### 4. 完整签名验证

要进行完整的签名验证（验证证书链），需要提供 C2PA 信任锚点文件。

首先从 [C2PA Trust Lists](https://opensource.contentauthenticity.org/docs/conformance/trust-lists) 下载信任列表 PEM 文件，然后运行：

```bash
cargo run -p verifier -- --file <图片路径> --trust-anchors <信任列表.pem>
```

或者使用 settings 文件：

```bash
cargo run -p verifier -- --file <图片路径> --settings <settings文件>
```

## 输出说明

### 验证成功（有 C2PA manifest）

```
=== C2PA Verification Results ===

✓ Verification Status: PASSED

--- Manifest Info ---
✓ C2PA Manifest: Found
  Label: <manifest标签>
  Claim Generator: <生成器信息>
  Title: <标题>

--- Ingredients (N items) ---
  - <文件名> (<格式>): ✓ with manifest / ✗ no manifest

================================
```

### 验证成功（无 C2PA manifest）

```
=== C2PA Verification Results ===

✓ Verification Status: PASSED

--- Manifest Info ---
✗ C2PA Manifest: Not Found

--- Warnings ---
  ⚠ No C2PA manifest found in the image

================================
```

### 验证失败

```
=== C2PA Verification Results ===

✗ Verification Status: FAILED

--- Manifest Info ---
✗ C2PA Manifest: Not Found

--- Errors ---
  ✗ <错误信息>

================================
```

## 程序参数

| 参数 | 简写 | 说明 |
|------|------|------|
| `--file` | `-f` | 图片文件路径 |
| `--base64` | - | Base64 编码的图片数据 |
| `--settings` | `-s` | 信任设置文件路径（可选） |
| `--trust-anchors` | `-t` | 信任锚点 PEM 文件路径（可选） |
| `--verbose` | `-v` | 详细输出模式 |

## 运行测试

```bash
# 运行所有单元测试
cargo test -p verifier
```

## 依赖

- Rust 2024 edition
- c2pa = "0.76" (with file_io feature)
- clap = "4.5"
- base64 = "0.22"
- serde = "1.0"
- serde_json = "1.0"

## 注意事项

1. 没有 C2PA manifest 的图片会被标记为 "PASSED" 但会显示警告 "No C2PA manifest found"
2. 完整的签名验证需要提供信任锚点文件
3. 支持的图片格式：JPEG, PNG, WebP, GIF, AVIF
