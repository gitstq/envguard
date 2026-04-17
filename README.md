# EnvGuard 🔒

<div align="center">

**Environment Variable Security Auditor**

*A zero-dependency CLI tool to detect sensitive information leaks in .env files*

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-gitstq%2Fenvguard-blue?logo=github)](https://github.com/gitstq/envguard)

[English](#english) | [简体中文](#简体中文) | [繁體中文](#繁體中文)

</div>

---

<a name="english"></a>

## 🇺🇸 English

### 🎉 Introduction

**EnvGuard** is a powerful, zero-dependency CLI tool that scans your `.env` files for sensitive information leaks. With **52 built-in security rules**, it detects API keys, tokens, passwords, and other secrets before they reach your repository.

**Inspired by**: The common security mistake of committing `.env` files with real credentials. EnvGuard helps developers catch these issues early in the development cycle.

### ✨ Key Features

- 🔐 **52 Built-in Security Rules** - AWS, GitHub, Stripe, OpenAI, JWT, and more
- 🚀 **Zero Dependencies** - Pure Python standard library, no pip install required
- 📊 **Multiple Output Formats** - Terminal, JSON, Markdown, SARIF (GitHub Security)
- 🔍 **Smart Pattern Detection** - Both key names and value patterns
- ⚡ **Fast & Lightweight** - Scans hundreds of files in seconds
- 🤖 **CI/CD Ready** - Exit codes and SARIF support for automation

### 🚀 Quick Start

```bash
# Install
pip install envguard

# Scan current directory
envguard scan

# Scan specific file
envguard scan .env

# Output as JSON
envguard scan -f json

# Save report
envguard scan -o report.md -f markdown
```

### 📖 Usage

#### Scan Command

```bash
# Basic scan
envguard scan

# Scan specific directory
envguard scan ./myproject

# Filter by severity
envguard scan --severity high

# Multiple formats
envguard scan -f json      # JSON output
envguard scan -f markdown  # Markdown report
envguard scan -f sarif     # GitHub Security format
```

#### Other Commands

```bash
# List all security rules
envguard rules

# Find all .env files
envguard find
```

### 💡 Design Philosophy

EnvGuard follows the **security-first** principle:
- **Zero trust** - Every `.env` variable is a potential risk
- **False positives over false negatives** - Better to warn than to miss
- **Developer-friendly** - Clear suggestions for every finding

### 📦 Installation

```bash
# From PyPI
pip install envguard

# From source
git clone https://github.com/gitstq/envguard.git
cd envguard
pip install -e .
```

### 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'feat: Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<a name="简体中文"></a>

## 🇨🇳 简体中文

### 🎉 项目介绍

**EnvGuard** 是一款强大的零依赖CLI工具，用于扫描 `.env` 文件中的敏感信息泄露。内置 **52条安全规则**，在敏感数据进入仓库前检测API密钥、令牌、密码等机密信息。

**灵感来源**: 开发者常犯的安全错误——将包含真实凭据的 `.env` 文件提交到仓库。EnvGuard帮助开发者在开发周期早期发现这些问题。

### ✨ 核心特性

- 🔐 **52条内置安全规则** - 覆盖AWS、GitHub、Stripe、OpenAI、JWT等
- 🚀 **零依赖** - 纯Python标准库，无需pip安装额外依赖
- 📊 **多种输出格式** - 终端、JSON、Markdown、SARIF（GitHub安全）
- 🔍 **智能模式检测** - 同时检测键名和值模式
- ⚡ **快速轻量** - 秒级扫描数百个文件
- 🤖 **CI/CD就绪** - 支持退出码和SARIF格式自动化

### 🚀 快速开始

```bash
# 安装
pip install envguard

# 扫描当前目录
envguard scan

# 扫描指定文件
envguard scan .env

# JSON格式输出
envguard scan -f json

# 保存报告
envguard scan -o report.md -f markdown
```

### 📖 详细使用

#### 扫描命令

```bash
# 基础扫描
envguard scan

# 扫描指定目录
envguard scan ./myproject

# 按严重程度过滤
envguard scan --severity high

# 多种格式
envguard scan -f json      # JSON输出
envguard scan -f markdown  # Markdown报告
envguard scan -f sarif     # GitHub安全格式
```

#### 其他命令

```bash
# 列出所有安全规则
envguard rules

# 查找所有.env文件
envguard find
```

### 💡 设计思路

EnvGuard遵循**安全优先**原则:
- **零信任** - 每个 `.env` 变量都是潜在风险
- **宁可误报不可漏报** - 警告总比遗漏好
- **开发者友好** - 每个发现都有清晰建议

### 📦 安装方式

```bash
# 从PyPI安装
pip install envguard

# 从源码安装
git clone https://github.com/gitstq/envguard.git
cd envguard
pip install -e .
```

### 🤝 贡献指南

欢迎贡献代码！

1. Fork本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'feat: 添加某个很棒的特性'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交Pull Request

### 📄 开源协议

本项目采用MIT协议 - 详见 [LICENSE](LICENSE) 文件。

---

<a name="繁體中文"></a>

## 🇹🇼 繁體中文

### 🎉 專案介紹

**EnvGuard** 是一款強大的零依賴CLI工具，用於掃描 `.env` 檔案中的敏感資訊外洩。內建 **52條安全規則**，在敏感資料進入倉庫前檢測API金鑰、令牌、密碼等機密資訊。

**靈感來源**: 開發者常犯的安全錯誤——將包含真實憑證的 `.env` 檔案提交到倉庫。EnvGuard幫助開發者在開發週期早期發現這些問題。

### ✨ 核心特性

- 🔐 **52條內建安全規則** - 覆蓋AWS、GitHub、Stripe、OpenAI、JWT等
- 🚀 **零依賴** - 純Python標準庫，無需pip安裝額外依賴
- 📊 **多種輸出格式** - 終端、JSON、Markdown、SARIF（GitHub安全）
- 🔍 **智慧模式檢測** - 同時檢測鍵名和值模式
- ⚡ **快速輕量** - 秒級掃描數百個檔案
- 🤖 **CI/CD就緒** - 支援退出碼和SARIF格式自動化

### 🚀 快速開始

```bash
# 安裝
pip install envguard

# 掃描當前目錄
envguard scan

# 掃描指定檔案
envguard scan .env

# JSON格式輸出
envguard scan -f json

# 儲存報告
envguard scan -o report.md -f markdown
```

### 📖 詳細使用

#### 掃描命令

```bash
# 基礎掃描
envguard scan

# 掃描指定目錄
envguard scan ./myproject

# 按嚴重程度過濾
envguard scan --severity high

# 多種格式
envguard scan -f json      # JSON輸出
envguard scan -f markdown  # Markdown報告
envguard scan -f sarif     # GitHub安全格式
```

#### 其他命令

```bash
# 列出所有安全規則
envguard rules

# 查找所有.env檔案
envguard find
```

### 💡 設計思路

EnvGuard遵循**安全優先**原則:
- **零信任** - 每個 `.env` 變數都是潛在風險
- **寧可誤報不可漏報** - 警告總比遺漏好
- **開發者友善** - 每個發現都有清晰建議

### 📦 安裝方式

```bash
# 從PyPI安裝
pip install envguard

# 從原始碼安裝
git clone https://github.com/gitstq/envguard.git
cd envguard
pip install -e .
```

### 🤝 貢獻指南

歡迎貢獻程式碼！

1. Fork本倉庫
2. 建立特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交變更 (`git commit -m 'feat: 新增某個很棒的功能'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交Pull Request

### 📄 開源協議

本專案採用MIT協議 - 詳見 [LICENSE](LICENSE) 檔案。

---

<div align="center">

**Made with ❤️ by [gitstq](https://github.com/gitstq)**

</div>
