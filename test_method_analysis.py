import csv
import json
import os
from openai import OpenAI
from src.prompts import METHOD_ANALYSIS_SYSTEM_PROMPT
from src.prompts import METHOD_ANALYSIS_USER_PROMPT

# 配置LLM客户端
client = OpenAI(
    api_key="sk-T1Vt6PLIOoBll7c2CkCsNOqtqB6rsdLcdcfrUyiXcOZOYDAD",
    base_url="https://api.chatanywhere.tech/v1"
)


def read_methods_from_csv(file_path):
    """从CSV文件读取方法信息"""
    methods = []
    fieldnames = []

    with open(file_path, mode='r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        fieldnames = reader.fieldnames.copy()
        for row in reader:
            # 构建方法的完整标识字符串
            method_info = f"{row['package']}.{row['clazz']}.{row['func']}: {row['full_signature']}"
            if row.get('doc') and row['doc'].strip():
                method_info += f"\nDocumentation: {row['doc']}"

            methods.append({
                'index': len(methods),
                'info': method_info,
                'row': row
            })

    return methods, fieldnames


def get_llm_analysis(methods):
    """调用LLM接口获取方法分析结果"""
    # 构建方法列表字符串
    method_list_str = "\n\n".join([f"Method {i}:\n{method['info']}" for i, method in enumerate(methods)])

    # 构建提示
    prompt = [
        {"role": "system", "content": METHOD_ANALYSIS_SYSTEM_PROMPT},
        {"role": "user", "content": METHOD_ANALYSIS_USER_PROMPT.format(method_list=method_list_str)}
    ]

    try:
        # 调用LLM API
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",  # 可根据需要更换模型
            messages=prompt,
            temperature=0.3,  # 降低随机性，使结果更稳定
            response_format={"type": "json_object"}
        )

        # 解析JSON响应
        analysis_results = json.loads(response.choices[0].message.content)
        return analysis_results

    except Exception as e:
        print(f"调用LLM接口时出错: {str(e)}")
        return None


def write_analyzed_csv(methods, fieldnames, output_file):
    """将包含分析结果的数据写入新CSV文件"""
    # 添加新列到字段名
    new_fieldnames = fieldnames + ['analysis']

    with open(output_file, mode='w', encoding='utf-8', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=new_fieldnames)
        writer.writeheader()

        for method in methods:
            # 复制原始行数据
            new_row = method['row'].copy()
            # 添加分析结果，如果有的话
            new_row['analysis'] = method.get('analysis', 'No analysis available')
            writer.writerow(new_row)


def main(input_csv, output_csv):
    """主函数：协调读取、分析和写入过程"""
    print(f"从 {input_csv} 读取方法数据...")
    methods, fieldnames = read_methods_from_csv(input_csv)

    if not methods:
        print("没有找到方法数据，程序退出。")
        return

    print(f"找到 {len(methods)} 个方法，正在请求LLM分析...")
    analysis_results = get_llm_analysis(methods)

    if analysis_results and 'analyses' in analysis_results:
        # 将分析结果与方法匹配
        for result in analysis_results['analyses']:
            index = result['method_index']
            if 0 <= index < len(methods):
                # 直接使用自然语言分析结果
                methods[index]['analysis'] = result['natural_language_analysis']

    print(f"将分析结果写入 {output_csv}...")
    write_analyzed_csv(methods, fieldnames, output_csv)

    print("处理完成！")


if __name__ == "__main__":
    # 输入和输出文件路径 - 可根据需要修改
    INPUT_CSV = "output/perwendel__spark_CVE-2018-9159_2.7.1/test2/common/source_func_test.csv"
    OUTPUT_CSV = "output/perwendel__spark_CVE-2018-9159_2.7.1/test2/common/source_func_analysis_test.csv"

    main(INPUT_CSV, OUTPUT_CSV)
