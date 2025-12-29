#!/bin/bash

echo "=== 下载 Restlet 2.1.1 核心包 (org.restlet) ==="
wget -O org.restlet-2.1.1.jar \
  https://repo.softmotions.com/repository/softmotions-public/org/restlet/jee/org.restlet/2.1.1/org.restlet-2.1.1.jar

echo "=== 下载 Restlet Servlet 扩展包 (org.restlet.ext.servlet) ==="
wget -O org.restlet.ext.servlet-2.1.1.jar \
  https://repo.softmotions.com/repository/softmotions-public/org/restlet/jee/org.restlet.ext.servlet/2.1.1/org.restlet.ext.servlet-2.1.1.jar

echo "=== 安装 org.restlet-2.1.1 到本地 Maven 仓库 ==="
mvn install:install-file \
  -Dfile=org.restlet-2.1.1.jar \
  -DgroupId=org.restlet.jee \
  -DartifactId=org.restlet \
  -Dversion=2.1.1 \
  -Dpackaging=jar

echo "=== 安装 org.restlet.ext.servlet-2.1.1 到本地 Maven 仓库 ==="
mvn install:install-file \
  -Dfile=org.restlet.ext.servlet-2.1.1.jar \
  -DgroupId=org.restlet.jee \
  -DartifactId=org.restlet.ext.servlet \
  -Dversion=2.1.1 \
  -Dpackaging=jar

echo "=== 完成！Restlet 2.1.1 已安装到本地 Maven 仓库 ==="
echo "现在可以构建 DSpace 或其他依赖 Restlet 2.1.1 的项目。"

