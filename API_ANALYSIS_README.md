# API Analysis Feature

## 概述

这个功能为 `collect_invoked_external_apis()` 方法添加了GPT模型分析能力，可以在生成的 `candidate_apis.csv` 文件中添加一个新的 `analysis` 列，用于存储对每个API的安全分析信息。

## 功能特点

1. **新增列**: 在原有的 `package`, `clazz`, `func`, `full_signature` 四列基础上，新增 `analysis` 列
2. **GPT分析**: 使用GPT模型对每个API进行安全分析
3. **批量处理**: 支持批量处理API，避免单次请求过大
4. **可配置**: 可以通过命令行参数控制是否启用分析功能
5. **错误处理**: 包含完善的错误处理机制

## 使用方法

### 1. 启用API分析功能

在运行主程序时添加 `--enable-api-analysis` 参数：

```bash
python src/neusym_vul.py your_project --query 022 --enable-api-analysis
```

### 2. 配置批量大小

可以通过 `--api-analysis-batch-size` 参数调整批量大小（默认为10）：

```bash
python src/neusym_vul.py your_project --query 022 --enable-api-analysis --api-analysis-batch-size 5
```

### 3. 输出文件

启用分析功能后，生成的 `candidate_apis.csv` 文件将包含以下列：

| 列名 | 描述 |
|------|------|
| package | API包名 |
| clazz | 类名 |
| func | 方法名 |
| full_signature | 完整方法签名 |
| analysis | GPT分析结果 |

## 分析内容

GPT模型会对每个API分析以下方面：

1. **功能描述**: API的主要功能和作用
2. **安全影响**: 潜在的安全风险和影响
3. **使用模式**: 常见的用法和模式
4. **安全考虑**: 使用时需要注意的安全事项

## 示例输出

```csv
package,clazz,func,full_signature,analysis
java.io,File,exists,boolean exists(),"File.exists() checks if a file exists on the filesystem. Security implications: Path traversal attacks possible if user input is used. Common usage: File validation. Security considerations: Validate file paths, avoid using user input directly."
java.net,URL,openConnection,URLConnection openConnection(),"URL.openConnection() creates a connection to a URL. Security implications: SSRF attacks possible. Common usage: HTTP requests. Security considerations: Validate URLs, use allowlists for allowed domains."
```

## 错误处理

- 如果GPT分析失败，对应的 `analysis` 列会显示 "Analysis failed for batch X"
- 如果功能被禁用，会显示 "Analysis disabled"
- 所有错误都会记录在日志中

## 性能考虑

- 批量处理可以减少API调用次数
- 建议根据API数量和GPT模型限制调整批量大小
- 分析过程会增加总体运行时间

## 测试

可以使用提供的测试脚本验证功能：

```bash
python test_api_analysis.py
```

## 注意事项

1. 需要配置有效的GPT模型API密钥
2. 分析功能会增加运行时间和API调用成本
3. 建议在测试环境中先验证功能
4. 大量API分析可能需要较长时间 