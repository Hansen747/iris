## 修改日志
### 1. ./data/cwe-bench-java/scripts/setup.py

* **jdk:** jdk-17 => jdk17.0.12, 对应的jdk_version.json也作了相应更改

* **mvn:** mvn3.9.8 => mvn3.9.11下载链接 404 not found, 对应的mvn_version.json也作了相应更改

* **build_one:** 将attempt键值对内部元素mvn更换为3.9.11

### 2. ./src/neusym_vul.py

* **line 1120:** 更改为json_str = re.findall("\\[[\\s\\S]*\\]", json_str)[0], 消除了语法警告

### 3. ./src/models/qwen.py

* **QwenModel(LLM):** 改为使用本地部署的Qwen--Qwen3-Next-80B-A3B-Instruct, 修改了构建函数和预测函数


## 运行日志
### non-analysis 运行
1. python3 src/neusym_vul.py wildfly__wildfly_CVE-2018-1047_11.0.0.Final --query cwe-022wLLM --llm gpt-3.5 --overwrite: 

    耗时 20 min 消耗5.28元

2. python3 src/neusym_vul.py vert-x3__vertx-web_CVE-2018-12542_3.5.3.CR1 --query cwe-022wLLM --llm qwen --overwrite:

    修改为本地Qwen以后,尝试运行

#### project_info.csv:
1,DSpace__DSpace_CVE-2016-10726_4.4,CVE-2016-10726,CWE-022,Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'),DSpace,DSpace,4.4,https://github.com/DSpace/DSpace,GHSA-4m9r-5gqp-7j82,ca4c86b1baa4e0b07975b1da86a34a6e7170b3b7,4239abd2dd2ae0dedd7edc95a5c9f264fdcf639d

✔ DSpace 4.4 是 2014–2015 年左右的代码

依赖的 Restlet 2.1.1 更老（2012 年）

✔ Restlet 仓库（maven.restlet.org）已经关闭

所以 Maven 下载到了 HTML 提示页面，而不是 JAR 文件。

✔ Maven 把 HTML 当成 JAR 存入 ~/.m2