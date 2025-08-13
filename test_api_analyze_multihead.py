import csv
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from openai import OpenAI  # 假设使用OpenAI兼容的API
from src.prompts import API_ANALYSIS_SYSTEM_PROMPT
from src.prompts import API_ANALYSIS_USER_PROMPT

# 配置LLM客户端 - 根据实际使用的API进行调整
client = OpenAI(
    api_key="sk-T1Vt6PLIOoBll7c2CkCsNOqtqB6rsdLcdcfrUyiXcOZOYDAD",
    base_url="https://api.chatanywhere.tech/v1"
)

# CWE相关内容（根据实际情况修改）
CWE_LONG_DESCRIPTION = """\
A path traversal vulnerability allows an attacker to access files \
on your web server to which they should not have access. They do this by tricking either \
the web server or the web application running on it into returning files that exist outside \
of the web root folder. Another attack pattern is that users can pass in malicious Zip file \
which may contain directories like "../". Typical sources of this vulnerability involves \
obtaining information from untrusted user input through web requests, getting entry directory \
from Zip files. Sinks will relate to file system manipulation, such as creating file, listing \
directories, and etc."""

CWE_EXAMPLES = """
- Source: java.io.InputStreamReader.read() reads untrusted input
- Sink: java.lang.Runtime.exec() executes system commands
- Propagator: java.lang.String.concat() passes data without validation
"""


def process_batch(batch_num, api_batch, start_idx, model_id, result_list, lock):
    """处理单个批次的API分析，线程安全的实现"""
    batch_length = len(api_batch)
    print(f"线程 {threading.current_thread().name} 开始处理批次 {batch_num + 1}，包含 {batch_length} 个API")

    # 生成当前批次的API列表（带本地序号）
    api_list = "\n".join([
        f"{i + 1}. {e['original_row']['package']}.{e['original_row']['clazz']}.{e['original_row']['func']}: {e['full_signature']}"
        for i, e in enumerate(api_batch)
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
            temperature=0.3
        )
        llm_output = response.choices[0].message.content.strip()
        print(f"线程 {threading.current_thread().name} 完成批次 {batch_num + 1} 分析")
    except Exception as e:
        print(f"线程 {threading.current_thread().name} 处理批次 {batch_num + 1} 失败: {str(e)}")
        return batch_num, 0  # 返回失败的批次号和0匹配数

    # 解析结果
    pattern = re.compile(r'^(\d+)\. (.*)$', re.MULTILINE)
    matches = pattern.findall(llm_output)

    # 线程安全地更新结果列表（使用锁避免竞争条件）
    batch_matches = 0
    with lock:
        for num_str, content in matches:
            try:
                batch_index = int(num_str) - 1
                global_index = start_idx + batch_index
                if 0 <= batch_index < batch_length and 0 <= global_index < len(result_list):
                    result_list[global_index] = content.strip()
                    batch_matches += 1
            except ValueError:
                continue

    print(f"线程 {threading.current_thread().name} 批次 {batch_num + 1} 匹配结果: {batch_matches}/{batch_length}")
    return batch_num, batch_matches


def analyze_apis(input_csv, output_csv, model_id="gpt-3.5-turbo", batch_size=30, max_workers=5):
    """
    多线程分析API与CWE漏洞的关联
    
    参数:
        max_workers: 最大线程数，根据API并发限制调整
    """
    # 读取CSV并收集API
    api_entries = []
    with open(input_csv, mode='r', newline='', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames + ['analysis']

        for row in reader:
            api_entries.append({
                'original_row': row,
                'full_signature': row['full_signature']
            })
    
    total_apis = len(api_entries)
    print(f"发现 {total_apis} 个API需要分析")
    
    if total_apis == 0:
        print("没有API需要分析，直接退出")
        return
    
    # 初始化分析结果列表和线程锁
    analysis_results = ["No analysis available"] * total_apis
    result_lock = threading.Lock()  # 保证结果写入的线程安全
    
    # 计算批次数并生成批次列表
    num_batches = (total_apis + batch_size - 1) // batch_size
    batches = []
    for batch_num in range(num_batches):
        start_idx = batch_num * batch_size
        end_idx = min((batch_num + 1) * batch_size, total_apis)
        batches.append((batch_num, api_entries[start_idx:end_idx], start_idx))
    
    print(f"将分为 {num_batches} 批进行分析，每批最多 {batch_size} 个API，使用 {max_workers} 个线程")
    
    # 多线程处理所有批次
    total_matches = 0
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="API-Analyzer") as executor:
        # 提交所有任务
        futures = [
            executor.submit(
                process_batch, 
                batch_num, 
                batch_data, 
                start_idx, 
                model_id, 
                analysis_results, 
                result_lock
            ) 
            for batch_num, batch_data, start_idx in batches
        ]
        
        # 等待所有任务完成并统计结果
        for future in as_completed(futures):
            try:
                batch_num, batch_matches = future.result()
                total_matches += batch_matches
            except Exception as e:
                print(f"处理批次时发生意外错误: {str(e)}")
    
    # 写入输出CSV
    with open(output_csv, mode='w', newline='', encoding='utf-8') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for i, entry in enumerate(api_entries):
            new_row = entry['original_row'].copy()
            new_row['analysis'] = analysis_results[i]
            writer.writerow(new_row)
    
    print(f"\n分析完成，结果已保存到 {output_csv}")
    print(f"API总数: {total_apis}, 成功匹配分析: {total_matches}")


if __name__ == "__main__":
    # 示例用法
    input_file = "/home/user01/hansen/iris/output/perwendel__spark_CVE-2016-9177_2.5.1/test2/cwe-022/candidate_apis.csv"
    output_file = "/home/user01/hansen/iris/output/perwendel__spark_CVE-2016-9177_2.5.1/test2/cwe-022/candidate_apis_test.csv"
    # 可根据API服务的并发限制调整max_workers（建议不要超过10）
    analyze_apis(input_file, output_file, batch_size=30, max_workers=5)
    