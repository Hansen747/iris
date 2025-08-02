import csv
import os
import re
from openai import OpenAI  # 假设使用OpenAI兼容的API
from src.prompts import API_ANALYSIS_SYSTEM_PROMPT
from src.prompts import API_ANALYSIS_USER_PROMPT

# 配置LLM客户端 - 根据实际使用的API进行调整
client = OpenAI(
    api_key="sk-T1Vt6PLIOoBll7c2CkCsNOqtqB6rsdLcdcfrUyiXcOZOYDAD",
    base_url="https://api.chatanywhere.tech/v1"
)

# CWE相关内容（根据实际情况修改）
CWE_LONG_DESCRIPTION = "CWE (Common Weakness Enumeration) identifies common software security weaknesses. " \
                       "Taint sources are APIs that introduce untrusted data, sinks are APIs that can execute " \
                       "untrusted data, and propagators move data between them."

CWE_EXAMPLES = """
- Source: java.io.InputStreamReader.read() reads untrusted input
- Sink: java.lang.Runtime.exec() executes system commands
- Propagator: java.lang.String.concat() passes data without validation
"""


def analyze_apis(input_csv, output_csv, model_id="gpt-3.5-turbo"):
    # 读取CSV并收集API
    api_entries = []
    with open(input_csv, mode='r', newline='', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames + ['analysis']

        for row in reader:
            api_entries.append({
                'original_row': row,
                'full_signature': row['full_signature']  # 用于日志核对
            })

    # 生成API列表（带序号，方便LLM对应）
    api_list = "\n".join([
        f"{i + 1}. {e['original_row']['package']}.{e['original_row']['clazz']}.{e['original_row']['func']}: {e['full_signature']}"
        for i, e in enumerate(api_entries)
    ])
    # 构建提示
    user_prompt = API_ANALYSIS_USER_PROMPT.format(
        cwe_long_description=CWE_LONG_DESCRIPTION,
        cwe_examples=CWE_EXAMPLES,
        api_list=api_list
    )

    prompt = [
        {"role": "system", "content": API_ANALYSIS_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt}
    ]

    # 调用LLM
    try:
        response = client.chat.completions.create(
            model=model_id,
            messages=prompt,
            temperature=0.3  # 降低随机性，保证格式稳定
        )
        llm_output = response.choices[0].message.content.strip()
    except Exception as e:
        print(f"LLM调用失败: {str(e)}")
        return

    # 解析结果：按序号提取每个API的分析（核心优化点）
    analysis_results = []
    # 用正则匹配带序号的行（例如"1. ...", "2. ..."）
    pattern = re.compile(r'^(\d+)\. (.*)$', re.MULTILINE)
    matches = pattern.findall(llm_output)  # 结果为[(序号, 分析内容), ...]

    # 按API数量初始化结果列表
    analysis_results = ["No analysis available"] * len(api_entries)
    for num_str, content in matches:
        try:
            index = int(num_str) - 1  # 转换为0-based索引
            if 0 <= index < len(api_entries):
                analysis_results[index] = content.strip()
        except ValueError:
            continue  # 忽略无效序号

    # 写入输出CSV
    with open(output_csv, mode='w', newline='', encoding='utf-8') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for i, entry in enumerate(api_entries):
            new_row = entry['original_row'].copy()
            new_row['analysis'] = analysis_results[i]
            writer.writerow(new_row)

    print(f"分析完成，结果已保存到 {output_csv}")
    # 打印匹配情况（方便调试）
    print(
        f"API总数: {len(api_entries)}, 成功匹配分析: {sum(1 for a in analysis_results if a != 'No analysis available')}")


if __name__ == "__main__":
    # 示例用法
    input_file = "output/Java-Projects-Beginner--main____/test1/cwe-022/candidate_apis.csv"  # 输入CSV文件路径
    output_file = "output/Java-Projects-Beginner--main____/test1/cwe-022/candidate_apis_test.csv"  # 输出CSV文件路径
    analyze_apis(input_file, output_file)
