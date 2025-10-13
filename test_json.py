# import json

# filename = "/home/cmcc/iris/output/DSpace__DSpace_CVE-2016-10726_4.4/test01_analysis/cwe-022/logs/label_apis/raw_llm_response_2880.txt"
# with open(filename, "r", encoding="utf-8") as f:
#     content = f.read()
#     indiv_results = []
#     json_result = json.loads(content)
#     indiv_results.append(json_result)
#     print(indiv_results)
import glob
import json
response_files = sorted(glob.glob("/home/cmcc/iris/output/DSpace__DSpace_CVE-2016-10726_4.4/test01_analysis/cwe-022/logs/label_apis/raw_llm_response_*.txt"))
all_results = []
for filename in response_files:
    with open(filename, "r", encoding="utf-8") as f:
        try:
            content = f.read()
            json_result = json.loads(content)
            if isinstance(json_result, list):
                all_results.extend(json_result)
            else:
                all_results.append(json_result)
        except Exception as e:
            print(f"解析 {filename} 失败: {e}")
# 按照原reload_cache格式保存
json.dump(all_results, open("/home/cmcc/iris/output/common/test01_analysis/cwe-022/api_labels_gpt-3.5.json", "w"), indent=2)