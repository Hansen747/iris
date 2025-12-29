### 数据集

**1. 项目构建**

**2. Codeql数据库构建**

eclipse__hawkbit_CVE-2020-27219_0.3.0M6无法构建

原因:该项目本身不是一个完整可编译的 Maven 项目，而是为复现 CVE 切出来的“最小化漏洞片段（minimal reproducer）”, 部分模块依赖缺失

fallback

codeql 不需要编译

long_desc

并发度+ (vllm)

**3. 流水线debug**


long_desc 四个cwe已有, 未加改动

apache__flink_CVE-2020-17519_1.11.2 无法编译 卡在build卡了半天

codeql_db编译完成,总计110个, 采用的compile-only

* codeql_db共110个项目 = 总的120个项目 - 编译失败的9个 - 无法编译的'apache__flink_CVE-2020-17519_1.11.2'

编译失败的9个:

* **1. apache__camel_CVE-2018-8041_2.20.3**: 依赖项下载页面404

    /home/agent/.m2/repository/org/restlet/jee/org.restlet/2.3.6/org.restlet-2.3.6.jar: HTML document, ASCII text, with very long lines (432)

    The JAR/ZIP file (...) org.restlet-2.3.6.jar seems corrupted  
    Caused by: java.util.zip.ZipException: error in opening zip file

* **2. apache__camel_CVE-2019-0194_2.21.4**:



* **3. asf__tapestry-5_CVE-2019-0207_5.4.4**: 构建系统被时代淘汰, 无法与服务器握手



* **4. DSpace__DSpace_CVE-2016-10726_4.4**:



* **5. eclipse-ee4j__glassfish_CVE-2022-2712_6.2.5**:



* **6. eclipse__hawkbit_CVE-2020-27219_0.3.0M6**:



* **7. Graylog2__graylog2-server_CVE-2023-41044_5.1.2**:



* **8. spring-projects__spring-security_CVE-2011-2732_2.0.6.RELEASE**: 依赖项缺失

    项目依赖了一个已经“消失”的 Maven 仓库  
    repository.springsource.com

* **9. x-stream__xstream_CVE-2020-26217_1.4.14-java7**: 原数据集错误标注为gradle项目, 不具备有效性


卡死在import torch:

1.apache__camel_CVE-2018-8041_2.20.3.log

2.apache__tika_CVE-2018-11762_1.18.log

3.dromara__hutool_CVE-2018-17297_4.1.11.log

4.DSpace__DSpace_CVE-2016-10726_4.4

5.perwendel__spark_CVE-2016-9177_2.5.1

6.perwendel__spark_CVE-2018-9159_2.7.1

7.vert-x3__vertx-web_CVE-2018-12542_3.5.3.CR1

codeql构建数据集陷入递归:

8.asf__karaf_CVE-2022-22932_4.3.5.log

9.apache__uima-uimaj_CVE-2022-32287_3.3.0

10.DSpace__DSpace_CVE-2022-31194_5.10

codeql内存栈溢出:

11.asf__james-project_CVE-2022-22931_3.6.0.log

12.aws__aws-sdk-java_CVE-2022-31159_1.12.260

13.yamcs__yamcs_CVE-2023-45277_5.8.6

14.yamcs__yamcs_CVE-2023-45278_5.8.6

15.hapifhir__org.hl7.fhir.core_CVE-2023-24057_5.6.91

16.hapifhir__org.hl7.fhir.core_CVE-2023-28465_5.6.105

17.keycloak__keycloak_CVE-2022-3782_20.0.1

18.payara__Payara_CVE-2022-37422_5.2022.2

19.spring-cloud__spring-cloud-config_CVE-2020-5405_2.1.6.RELEASE

20.testng-team__testng_CVE-2022-4065_7.5

21.vert-x3__vertx-web_CVE-2019-17640_3.9.3

22.whitesource__curekit_CVE-2022-23082_1.1.3

23.wildfly__wildfly_CVE-2018-1047_11.0.0.Final


1. dromara__hutool_CVE-2018-17297_4.1.11

2. DSpace__DSpace_CVE-2022-31194_5.10 

3. asf__karaf_CVE-2022-22932_4.3.5

4. apache__uima-uimaj_CVE-2022-32287_3.3.0 

5. asf__james-project_CVE-2022-22931_3.6.0

cant find:
apache__camel_CVE-2018-8041_2.20.3      ✅
apache__camel_CVE-2019-0194_2.21.4      ✅
asf__tapestry-5_CVE-2019-0207_5.4.4     ✅
DSpace__DSpace_CVE-2016-10726_4.4       ✅
payara__Payara_CVE-2022-37422_5.2022.2  ❌❌
perwendel__spark_CVE-2016-9177_2.5.1    ❌✅
spring-cloud__spring-cloud-config_CVE-2020-5405_2.1.6.RELEASE ❌✅
spring-cloud__spring-cloud-config_CVE-2020-5410_2.1.8.RELEASE ❌
testng-team__testng_CVE-2022-4065_7.5 ❌
vert-x3__vertx-web_CVE-2019-17640_3.9.3 ❌
