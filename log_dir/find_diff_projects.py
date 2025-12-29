#!/usr/bin/env python3
"""
脚本用于比较 analysis 和 non_analysis 的结果，找出 recall_file 从 false 变为 true 的项目
"""

import argparse
import csv
import json
import os
from pathlib import Path


def extract_cwe_from_query(query):
    """从 query 中提取 CWE ID，例如从 'cwe-022wLLM' 提取 'CWE-022'"""
    # 查找 cwe- 后面的数字
    import re
    match = re.search(r'cwe-(\d+)', query, re.IGNORECASE)
    if match:
        return f"CWE-{match.group(1).zfill(3)}"
    return None


def load_project_info(csv_path, cwe_id):
    """从 project_info.csv 中加载指定 CWE 的项目列表"""
    projects = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['cwe_id'] == cwe_id:
                projects.append(row['project_slug'])
    return projects


def get_recall_file_value(results_json_path):
    """从 results.json 中读取 posthoc_filter_result.recall_file 的值"""
    try:
        with open(results_json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('posthoc_filter_result', {}).get('recall_file', None)
    except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
        return None


def main():
    parser = argparse.ArgumentParser(description='比较 analysis 和 non_analysis 的结果')
    parser.add_argument('--run-id', required=True, help='运行 ID，例如 default 或 1234')
    parser.add_argument('--query', required=True, help='查询名称，例如 cwe-022wLLM')
    
    args = parser.parse_args()
    
    # 路径配置
    base_dir = Path.home() / 'iris'
    log_dir = base_dir / 'log_dir'
    project_info_csv = base_dir / 'data' / 'cwe-bench-java' / 'data' / 'project_info.csv'
    output_dir = base_dir / 'output'
    find_diff_dir = log_dir / 'find_diff'
    
    # 创建 find_diff 文件夹
    find_diff_dir.mkdir(parents=True, exist_ok=True)
    
    # 从 query 中提取 CWE ID
    cwe_id = extract_cwe_from_query(args.query)
    if not cwe_id:
        print(f"错误: 无法从 query '{args.query}' 中提取 CWE ID")
        return
    
    print(f"提取的 CWE ID: {cwe_id}")
    
    # 加载项目列表
    if not project_info_csv.exists():
        print(f"错误: 找不到项目信息文件 {project_info_csv}")
        return
    
    projects = load_project_info(project_info_csv, cwe_id)
    print(f"找到 {len(projects)} 个 {cwe_id} 项目")
    
    # 查找符合条件的项目
    matching_projects = []
    not_found_projects = []

    for project_slug in projects:
        project_dir = output_dir / project_slug
        
        if not project_dir.exists():
            continue
        
        # 构建两个 results.json 的路径
        analysis_results = project_dir / f"{args.run_id}_analysis" / f"{args.query}-final" / "results.json"
        non_analysis_results = project_dir / f"{args.run_id}_non_analysis" / f"{args.query}-final" / "results.json"
        
        if not analysis_results.exists():
            print(f"analysis_results not found: {analysis_results}")
            not_found_projects.append(project_slug)
            continue
        if not non_analysis_results.exists():
            print(f"non_analysis_results not found: {non_analysis_results}")
            not_found_projects.append(project_slug)
            continue

        # 读取 recall_file 值
        analysis_recall = get_recall_file_value(analysis_results)
        non_analysis_recall = get_recall_file_value(non_analysis_results)
        
        # 检查条件：non_analysis 为 false，analysis 为 true
        if non_analysis_recall is False and analysis_recall is True:
            matching_projects.append(project_slug)
            print(f"找到匹配项目: {project_slug}")
    
    # 写入 CSV 文件，包括未找到的项目
    output_csv = find_diff_dir / f"{args.query}_{args.run_id}.csv"
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['project_slug', 'analysis_results', 'non_analysis_results'])
        for project in matching_projects:
            writer.writerow([project, analysis_results, non_analysis_results])
        for project in not_found_projects:
            writer.writerow([project, "not found", "not found"])
    
    print(f"\n完成! 找到 {len(matching_projects)} 个符合条件的项目")
    print(f"结果已保存到: {output_csv}")


if __name__ == '__main__':
    main()