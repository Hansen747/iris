import os
import csv
import sys
import subprocess as sp
import threading
import time
import pandas as pd
import shutil
import json
import re
import argparse
import numpy as np
import copy
import math
import random
from openai import OpenAI  # 假设使用OpenAI兼容的API
import requests
from tqdm import tqdm
from tqdm.contrib.concurrent import thread_map
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

THIS_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
NEUROSYMSA_ROOT_DIR = os.path.abspath(f"{THIS_SCRIPT_DIR}/../")
sys.path.append(NEUROSYMSA_ROOT_DIR)

from src.config import CODEQL_DIR, CODEQL_DB_PATH, PACKAGE_MODULES_PATH, OUTPUT_DIR, ALL_METHOD_INFO_DIR, PROJECT_SOURCE_CODE_DIR, CVES_MAPPED_W_COMMITS_DIR


from src.logger import Logger
from src.queries import QUERIES
from src.prompts import API_ANALYSIS_SYSTEM_PROMPT, API_ANALYSIS_USER_PROMPT
from src.prompts import METHOD_ANALYSIS_USER_PROMPT,METHOD_ANALYSIS_SYSTEM_PROMPT
from src.prompts import API_LABELLING_SYSTEM_PROMPT, API_LABELLING_USER_PROMPT
from src.prompts import FUNC_PARAM_LABELLING_SYSTEM_PROMPT, FUNC_PARAM_LABELLING_USER_PROMPT

from src.codeql_queries import QL_SOURCE_PREDICATE, QL_STEP_PREDICATE, QL_SINK_PREDICATE
from src.codeql_queries import EXTENSION_YML_TEMPLATE, EXTENSION_SRC_SINK_YML_ENTRY, EXTENSION_SUMMARY_YML_ENTRY
from src.codeql_queries import QL_METHOD_CALL_SOURCE_BODY_ENTRY, QL_FUNC_PARAM_SOURCE_ENTRY, QL_FUNC_PARAM_NAME_ENTRY
from src.codeql_queries import QL_SUMMARY_BODY_ENTRY, QL_BODY_OR_SEPARATOR
from src.codeql_queries import QL_SUBSET_PREDICATE, CALL_QL_SUBSET_PREDICATE
from src.codeql_queries import QL_SINK_BODY_ENTRY, QL_SINK_ARG_NAME_ENTRY, QL_SINK_ARG_THIS_ENTRY

from src.modules.codeql_query_runner import CodeQLQueryRunner
from src.modules.contextual_analysis_pipeline import ContextualAnalysisPipeline
from src.modules.evaluation_pipeline import EvaluationPipeline

from src.models.llm import LLM

CODEQL = f"{CODEQL_DIR}/codeql"
CODEQL_CUSTOM_QUERY_DIR = f"{CODEQL_DIR}/qlpacks/codeql/java-queries/0.8.3/myqueries"
CODEQL_CUSTOM_YML_DIR = f"{CODEQL_DIR}/qlpacks/codeql/java-queries/0.8.3/.codeql/libraries/codeql/java-all/0.8.3/ext"

PRIMITIVE_TYPES = set([
    "void",
    "int",
    "boolean",
    "long",
    "Integer",
    "Boolean",
    "Object",
])

MAX_DOC_LENGTH = 50


class SAPipeline:
    def __init__(self,
            project_name: str,
            query: str,
            run_id: str = "default",
            llm: str = "gpt-4",
            label_api_batch_size: int = 30,
            label_func_param_batch_size: int = 50,
            num_threads: int = 3,
            seed: int = 1234,
            no_summary_model: bool = False,
            use_exhaustive_qll: bool = False,
            skip_huge_project: bool = False,
            skip_huge_project_num_apis_threshold: int = 3000,
            skip_posthoc_filter: bool = False,
            skip_evaluation: bool = False,
            filter_by_module: bool = False,
            filter_by_module_large: bool = False,
            posthoc_filtering_skip_fp: bool = False,
            posthoc_filtering_rerun_skipped_fp: bool = False,
            evaluation_only: bool = False,
            overwrite: bool = False,
            overwrite_api_candidates: bool = False,
            overwrite_func_param_candidates: bool = False,
            overwrite_labelled_apis: bool = False,
            overwrite_llm_cache: bool = False,
            overwrite_labelled_func_param: bool = False,
            overwrite_cwe_query_result: bool = False,
            overwrite_postprocess_cwe_query_result: bool = False,
            overwrite_posthoc_filter: bool = False,
            overwrite_debug_info: bool = False,
            debug_source: bool = False,
            debug_sink: bool = False,
            test_run: bool = False,
            no_logger: bool = False,
            overwrite_analyze_api: bool = False,
            overwrite_analyze_func: bool = False,
            analysis: bool = False,
            model_name: str = 'all-MiniLM-L6-v2',
            similarity_threshold: float = 0.85,
            skip_api_transmit: bool = False,
            skip_func_transmit: bool = False
    ):
        # Store basic information
        self.project_name = project_name
        self.query = query
        self.llm = llm
        self.label_api_batch_size = label_api_batch_size
        self.label_func_param_batch_size = label_func_param_batch_size
        self.num_threads = num_threads
        self.seed = seed
        self.run_id = run_id
        self.no_summary_model = no_summary_model
        self.use_exhaustive_qll = use_exhaustive_qll
        self.skip_huge_project = skip_huge_project
        self.skip_huge_project_num_apis_threshold = skip_huge_project_num_apis_threshold
        self.skip_posthoc_filter = skip_posthoc_filter
        self.skip_evaluation = skip_evaluation
        self.filter_by_module = filter_by_module
        self.filter_by_module_large = filter_by_module_large
        self.posthoc_filtering_skip_fp = posthoc_filtering_skip_fp
        self.posthoc_filtering_rerun_skipped_fp = posthoc_filtering_rerun_skipped_fp
        self.evaluation_only = evaluation_only
        self.overwrite = overwrite
        self.overwrite_api_candidates = overwrite_api_candidates
        self.overwrite_func_param_candidates = overwrite_func_param_candidates
        self.overwrite_labelled_apis = overwrite_labelled_apis
        self.overwrite_llm_cache = overwrite_llm_cache
        self.overwrite_labelled_func_param = overwrite_labelled_func_param
        self.overwrite_cwe_query_result = overwrite_cwe_query_result
        self.overwrite_postprocess_cwe_query_result = overwrite_postprocess_cwe_query_result
        self.overwrite_posthoc_filter = overwrite_posthoc_filter
        self.overwrite_debug_info = overwrite_debug_info
        self.debug_source = debug_source
        self.debug_sink = debug_sink
        self.test_run = test_run
        self.no_logger = no_logger
        self.overwrite_analyze_api = overwrite_analyze_api
        self.overwrite_analyze_func = overwrite_analyze_func
        self.analysis = analysis
        self.skip_api_transmit = skip_api_transmit
        self.skip_func_transmit = skip_func_transmit
        # 标签传播相关参数和成员变量
        self.model_name = model_name
        self.similarity_threshold = similarity_threshold
        self.vector_db_apis = []  # API向量数据库
        self.vector_db_func_params = []  # 函数参数向量数据库
        self.labelled_apis = {
            'source': [],
            'sink': [],
            'taint-propagator': []
        }  # 已标记的API
        self.labelled_func_params = []  # 已标记的函数参数
        
        # 初始化句子转换模型
        self.embedding_model = SentenceTransformer(model_name)

        # Setup logger
        if not self.no_logger:
            self.master_logger = Logger(f"{NEUROSYMSA_ROOT_DIR}/log")

        # Check if the query is valid
        if self.query in QUERIES:
            if "cwe_id" not in QUERIES[self.query]:
                if not self.no_logger:
                    self.master_logger.info(f"Processing {self.project_name} (Query: {self.query}, Trial: {self.run_id})...")
                    self.master_logger.error(f"==> Query `{self.query}` is not a query for detecting CWE; aborting")
                raise Exception(f"Query `{self.query}` is not a query for detecting CWE; aborting")
        else:
            if not self.no_logger:
                self.master_logger.info(f"Processing {self.project_name} (Query: {self.query}, Trial: {self.run_id})...")
                self.master_logger.error(f"==> Unknown query `{self.query}`; aborting")
            raise Exception(f"Unknown query `{self.query}`; aborting")
        self.cwe_id = QUERIES[self.query]["cwe_id"]
        self.cve_id = project_name.split("_")[3]

        # Load some basic information, such as commits and fixes related to the CVE
        self.project_source_code_dir = f"{PROJECT_SOURCE_CODE_DIR}/{self.project_name}"
        if self.cve_id is not None and self.cve_id.startswith("CVE-"):
            self.all_cves_with_commit = pd.read_csv(CVES_MAPPED_W_COMMITS_DIR)
            self.project_cve_with_commit_info = self.all_cves_with_commit[self.all_cves_with_commit["cve_id"] == self.cve_id].iloc[0]
            self.cve_fixing_commits = self.project_cve_with_commit_info["fix_commit_ids"].split(";")
        else:
            self.cve_fixing_commits = []
        self.fixed_methods = pd.read_csv(ALL_METHOD_INFO_DIR)
        self.project_fixed_methods = self.fixed_methods[self.fixed_methods["project_slug"] == self.project_name]
        self.project_fixed_modules = self.project_fixed_methods[
            self.project_fixed_methods["file"].str.contains("src/main") &
            self.project_fixed_methods["file"].str.endswith(".java")]
        #lambda函数的作用是从每一行的方法文件路径中提取出模块名称。
        self.fixed_modules = self.project_fixed_modules \
            .apply(lambda f: \
                pd.Series([
                    f["file"][:f["file"].index("src/main") - 1] if f["file"].index("src/main") > 1 else ""
                ], index=["module"]), axis=1, result_type="expand") \
            .drop_duplicates()

        # Basic path information
        if self.analysis:
            self.project_output_path = f"{OUTPUT_DIR}/{self.project_name}/{self.run_id}_analysis"
        else:
            self.project_output_path = f"{OUTPUT_DIR}/{self.project_name}/{self.run_id}_non_analysis"

        # Setup codeql database path
        self.project_codeql_db_path = f"{CODEQL_DB_PATH}/{self.project_name}"
        if not os.path.exists(f"{self.project_codeql_db_path}/db-java"):
            if not self.no_logger:
                self.master_logger.info(f"Processing {self.project_name} (Query: {self.query}, Trial: {self.run_id})...")
                self.master_logger.error(f"==> Cannot find CodeQL database for {self.project_name}; aborting")
            raise Exception(f"Cannot find CodeQL database for {self.project_codeql_db_path}; aborting")

        # Setup cwe output path
        self.cwe_output_path = f"{self.project_output_path}/cwe-{self.cwe_id}"
        os.makedirs(self.cwe_output_path, exist_ok=True)
        self.common_output_path = f"{self.project_output_path}/common"
        os.makedirs(self.common_output_path, exist_ok=True)

        # Path towards candidate APIs CSV files
        self.external_apis_csv_path = f"{self.cwe_output_path}/external_apis.csv"
        self.candidate_apis_csv_path = f"{self.cwe_output_path}/candidate_apis.csv"
        self.analysed_apis_csv_path = f"{self.cwe_output_path}/analysed_apis.csv"#被分析的外部api
        self.llm_labelled_sink_apis_path = f"{self.cwe_output_path}/llm_labelled_sink_apis.json"
        self.llm_labelled_source_apis_path = f"{self.cwe_output_path}/llm_labelled_source_apis.json"
        self.llm_labelled_taint_prop_apis_path = f"{self.cwe_output_path}/llm_labelled_taint_prop_apis.json"

        # Path towards candidate func params CSV files
        self.func_param_path = f"{self.common_output_path}/func_params.csv"
        self.source_func_param_candidates_path = f"{self.common_output_path}/source_func_param_candidates.csv"
        self.analysed_func_params_path = f"{self.common_output_path}/analysed_func_params.csv"#被分析的内部方法
        self.llm_labelled_source_func_params_path = f"{self.common_output_path}/llm_labelled_source_func_params.json"

        # LLM related log paths
        self.label_api_log_path = f"{self.cwe_output_path}/logs/label_apis"
        self.label_func_params_log_path = f"{self.common_output_path}/logs/label_func_params"
        os.makedirs(self.label_api_log_path, exist_ok=True)
        os.makedirs(self.label_func_params_log_path, exist_ok=True)

        # CodeQL queries temporary path
        self.source_qll_path = f"{self.cwe_output_path}/MySources.qll"
        self.summary_qll_path = f"{self.cwe_output_path}/MySummaries.qll"
        self.sink_qll_path = f"{self.cwe_output_path}/MySinks.qll"
        self.spec_yml_path = f"{self.cwe_output_path}/Spec.yml"

        # Setup query output path
        self.query_output_path = f"{self.project_output_path}/{self.query}"
        os.makedirs(self.query_output_path, exist_ok=True)
        self.query_output_result_sarif_path = f"{self.query_output_path}/results.sarif"
        self.query_output_result_csv_path = f"{self.query_output_path}/results.csv"
        self.query_output_result_sarif_pp_path = f"{self.query_output_path}/results_pp.sarif"

        # Setup posthoc-filtering output path
        self.posthoc_filtering_output_path = f"{self.project_output_path}/{self.query}-posthoc-filter"
        os.makedirs(self.posthoc_filtering_output_path, exist_ok=True)
        self.posthoc_filtering_output_result_sarif_path = f"{self.posthoc_filtering_output_path}/results.sarif"
        self.posthoc_filtering_output_result_json_path = f"{self.posthoc_filtering_output_path}/results.json"
        self.posthoc_filtering_output_stats_json_path = f"{self.posthoc_filtering_output_path}/stats.json"
        self.posthoc_filtering_output_log_path = f"{self.posthoc_filtering_output_path}/logs"
        os.makedirs(self.posthoc_filtering_output_log_path, exist_ok=True)

        # Setup final output path
        self.final_output_path = f"{self.project_output_path}/{self.query}-final"
        os.makedirs(self.final_output_path, exist_ok=True)
        self.final_output_json_path = f"{self.final_output_path}/results.json"

        # Function and Class locations
        self.func_locs_path = f"{self.project_output_path}/fetch_func_locs/results.csv"
        self.class_locs_path = f"{self.project_output_path}/fetch_class_locs/results.csv"

        # Create logger
        if not self.no_logger:
            self.project_logging_directory = f"{self.project_output_path}/log"
            os.makedirs(self.project_logging_directory, exist_ok=True)
            self.project_logger = Logger(self.project_logging_directory)
            self.project_logger.info(f"Processing {self.project_name} (Query: {self.query}, Trial: {self.run_id})...")
        else:
            self.project_logger = None

        # Setup cache path
        if not self.analysis:
            self.common_cache_path = f"{OUTPUT_DIR}/common/{self.run_id}_non_analysis/cwe-{self.cwe_id}"
        else:
            self.common_cache_path = f"{OUTPUT_DIR}/common/{self.run_id}_analysis/cwe-{self.cwe_id}"
        if not os.path.exists(self.common_cache_path):
            os.makedirs(self.common_cache_path, exist_ok=True)
        self.api_labels_cache_path = f"{self.common_cache_path}/api_labels_{self.llm}.json"
        self.model = None

    def get_model(self):
        if self.model is None:
            self.model = LLM.get_llm(model_name=self.llm, logger=self.project_logger, kwargs={"seed": self.seed, "max_new_tokens": 2048})
        return self.model

    def run_simple_codeql_query(self, query, target_csv_path=None, suffix=None, dyn_queries={}):
        runner = CodeQLQueryRunner(self.project_name, self.project_output_path, self.project_codeql_db_path, self.project_logger)
        runner.run(query, target_csv_path, suffix, dyn_queries)

    def keep_external_packages(self, api_candidates_df):
        packages = open(f"{PACKAGE_MODULES_PATH}/{self.project_name}.txt").readlines()
        packages = [p.strip() for p in packages]
        return api_candidates_df[~api_candidates_df["package"].isin(packages)]

    def keep_internal_packages(self, api_candidates_df):
        packages = open(f"{PACKAGE_MODULES_PATH}/{self.project_name}.txt").readlines()
        packages = [p.strip() for p in packages]
        return api_candidates_df[api_candidates_df["package"].isin(packages)]

    def api_candidate_is_in_fixed_module(self, external_api_candidate_row):
        if len(self.fixed_modules) > 0:
            return any(f"{s}/src/main" in external_api_candidate_row["location"] for s in self.fixed_modules["module"])
        else:
            return True

    def api_candidate_has_non_trivial_return(self, external_api_candidate_row):
        """
        A candidate has non trivial return if the candidate is a constructor or return non primitive type
        """
        if external_api_candidate_row["callstr"].startswith("new "): return True
        else: return external_api_candidate_row["return_type"] not in PRIMITIVE_TYPES

    def api_candidate_has_non_trivial_parameter(self, row):
        """
        A candidate has non trivial parameter if the candidate is
        1. static method with at least one non-trivial parameter
        2. non-static method
        """
        if row["is_static"]:
            param_types_raw = "" if type(row["parameter_types"]) == float else row["parameter_types"]
            param_types = param_types_raw.split(";")
            return any(param_ty not in PRIMITIVE_TYPES for param_ty in param_types)
        else:
            return True

    def api_candidate_not_on_blacklist(self, external_api_candidate_row):
        row = external_api_candidate_row
        if row["package"] == "java.util" and row["clazz"] == "String": return False
        if row["package"] == "java.util" and row["clazz"] == "EnumSet": return False
        if row["package"] == "java.util" and row["clazz"] == "LinkedList": return False
        if row["package"] == "java.util" and row["clazz"] == "List": return False
        if row["package"] == "java.io" and row["clazz"] == "PrintStream": return False
        else: return True

    def api_is_candidate(self, candidate, num_external_apis):
        if self.api_candidate_not_on_blacklist(candidate):
            if self.filter_by_module and not self.api_candidate_is_in_fixed_module(candidate):
                return False
            elif self.filter_by_module_large and num_external_apis >  self.skip_huge_project_num_apis_threshold and not self.api_candidate_is_in_fixed_module(candidate):
                return False
            return self.api_candidate_has_non_trivial_parameter(candidate) or \
                   self.api_candidate_has_non_trivial_return(candidate)
        else:
            return False

    def collect_invoked_external_apis(self):
        self.project_logger.info("==> Stage 1: Collecting external APIs...")

        # 1. Invoke CodeQL to extract the external APIs
        if not os.path.exists(self.external_apis_csv_path) or self.overwrite or self.overwrite_api_candidates:
            self.project_logger.info("  ==> Extracting all external APIs by running CodeQL... ", no_new_line=True)
            self.run_simple_codeql_query("fetch_external_apis", self.external_apis_csv_path)
            self.project_logger.print("Done.")
        else:
            self.project_logger.info("  ==> Existing external APIs file found. Skipping running CodeQL...")

        # 2. Load the API candidates
        if not os.path.exists(self.candidate_apis_csv_path) or self.overwrite or self.overwrite_api_candidates:
            external_api_candidates = pd.read_csv(self.external_apis_csv_path)
            num_external_apis = len(external_api_candidates)

            # 3. Filter the APIs by internal/external, and source/sink/taint-prop
            external_api_candidates = self.keep_external_packages(external_api_candidates)
            possible_src_snk_tp = external_api_candidates.apply(lambda row: self.api_is_candidate(row, num_external_apis), axis=1)
            #self.api_is_candidate 方法会根据某些条件判断该行代表的API是否是候选API。这些条件包括：
            # 是否在黑名单中（通过 self.api_candidate_not_on_blacklist 方法判断）。
            # 是否属于的模块（通过 self.api_candidate_is_in_fixed_module 方法判断）。
            # 是否具有非平凡的返回类型（通过 self.api_candidate_has_non_trivial_return 方法判断）。
            # 是否具有非平凡的参数类型（通过 self.api_candidate_has_non_trivial_parameter 方法判断）。
            external_api_candidates = external_api_candidates[possible_src_snk_tp]

            # 4. Keep only the core columns (package, class, function, signature) and deduplicate
            external_api_candidates = external_api_candidates[["package", "clazz", "func", "full_signature"]].drop_duplicates()
            num_candidates = len(external_api_candidates)

            # 5. Dump the filtered API candidates
            self.project_logger.info(f"  ==> #Relevant API Calls: {num_external_apis}, #Filtered Candidates: {num_candidates}")
            self.project_logger.info("  ==> Dumping filtered API candidates...")
            external_api_candidates.to_csv(self.candidate_apis_csv_path, index=False, header=True, sep=',', encoding='utf-8')
        else:
            self.project_logger.info("  ==> Existing candidate APIs file found. Skipping filtering candidates...")

    def process_batch(self,batch_num, api_batch, start_idx, model_id, result_list, lock):
    #"""处理单个批次的API分析，线程安全的实现"""
        batch_length = len(api_batch)
        print(f"线程 {threading.current_thread().name} 开始处理批次 {batch_num + 1}，包含 {batch_length} 个API")

        # 生成当前批次的API列表（带本地序号）
        api_list = "\n".join([
            f"{i + 1}. {e['original_row']['package']}.{e['original_row']['clazz']}.{e['original_row']['func']}: {e['full_signature']}"
            for i, e in enumerate(api_batch)
        ])
        # 获取CWE信息
        try:
            cwe_description = QUERIES[self.query]["prompts"]["desc"]
            cwe_long_description = QUERIES[self.query]["prompts"]["long_desc"]
            cwe_examples = json.dumps(QUERIES[self.query]["prompts"]["examples"], indent=2)
        except KeyError as e:
            self.project_logger.error(f"CWE信息获取失败: 缺少键 {str(e)}")
            return
        # 构建提示
        user_prompt = API_ANALYSIS_USER_PROMPT.format(
            api_list=api_list,
            cwe_id=self.cwe_id,
            cwe_description=cwe_description
        )
        system_prompt = API_ANALYSIS_SYSTEM_PROMPT.format(
                    cwe_description=cwe_description,
                    cwe_id=self.cwe_id,
                    cwe_long_description=cwe_long_description,
                    cwe_examples=cwe_examples)
        prompt = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        # 配置LLM客户端 - 根据实际使用的API进行调整
        client = OpenAI(
            api_key="sk-T1Vt6PLIOoBll7c2CkCsNOqtqB6rsdLcdcfrUyiXcOZOYDAD",
            base_url="https://api.chatanywhere.org/v1"
        )
        # 调用LLM
        try:
            response = client.chat.completions.create(
                model=model_id,
                messages=prompt,
                temperature=0.3
            )
            llm_output = response.choices[0].message.content.strip()
            # self.project_logger.info(f"线程 {threading.current_thread().name} 批次 {batch_num + 1} LLM输出: {llm_output}")
            print(f"线程 {threading.current_thread().name} 完成批次 {batch_num + 1} 分析")
        except Exception as e:
            self.project_logger.error(f"线程 {threading.current_thread().name} 处理批次 {batch_num + 1} 失败: {str(e)}")
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

    def analyze_apis(self,model_id="gpt-3.5-turbo", batch_size=15, max_workers=8):
    # """
    # 多线程分析API与CWE漏洞的关联
    
    # 参数:
    #     max_workers: 最大线程数，根据API并发限制调整
    # """
        self.project_logger.info("==> Stage 2: analyze external APIs...")
        if not self.analysis:
            self.project_logger.info("==>No need for analysis， skip this step.")
        else:
            if not os.path.exists(self.analysed_apis_csv_path) or self.overwrite or self.overwrite_analyze_api:
            # 读取CSV并收集API
                api_entries = []
                with open(self.candidate_apis_csv_path, mode='r', newline='', encoding='utf-8') as infile:
                    reader = csv.DictReader(infile)
                    fieldnames = reader.fieldnames + ['analysis']

                    for row in reader:
                        api_entries.append({
                            'original_row': row,
                            'full_signature': row['full_signature']
                        })
                
                total_apis = len(api_entries)
                print(f"发现 {total_apis} 个API需要分析")
                self.project_logger.info(f"发现 {total_apis} 个API需要分析")
                
                if total_apis == 0:
                    print("没有API需要分析，直接退出")
                    self.project_logger.info("没有API需要分析，直接退出")
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
                self.project_logger.info(f"将分为 {num_batches} 批进行分析，每批最多 {batch_size} 个API，使用 {max_workers} 个线程")
                
                # 多线程处理所有批次
                total_matches = 0
                with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="API-Analyzer") as executor:
                    # 提交所有任务
                    futures = [
                        executor.submit(
                            self.process_batch, 
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
                            self.project_logger.error(f"处理批次时发生意外错误: {str(e)}")
                
                # 写入输出CSV
                with open(self.analysed_apis_csv_path, mode='w', newline='', encoding='utf-8') as outfile:
                    writer = csv.DictWriter(outfile, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for i, entry in enumerate(api_entries):
                        new_row = entry['original_row'].copy()
                        new_row['analysis'] = analysis_results[i]
                        writer.writerow(new_row)
                
                print(f"\n分析完成，结果已保存到 {self.analysed_apis_csv_path}")
                print(f"API总数: {total_apis}, 成功匹配分析: {total_matches}")
                self.project_logger.info(f"分析完成，结果已保存到 {self.analysed_apis_csv_path}，API总数: {total_apis}, 成功匹配分析: {total_matches}")
            else:
                self.project_logger.info("  ==> 已存在分析结果，跳过分析...")
    


    def func_parameter_has_non_trivial_parameter(self, row):
        param_types_raw = "" if type(row["parameter_types"]) == float else row["parameter_types"]
        param_types = param_types_raw.split(";")
        return any(param_ty not in PRIMITIVE_TYPES for param_ty in param_types)

    def func_parameter_not_on_blacklist(self, row):
        if row["func"] == "isEqual" or row["func"] == "toString" or row["func"] == "equals" or row["func"] == "canConvert" or row["func"] == "compareTo" or row["func"] == "compare":
            return False
        elif "src/test" in row["location"]:
            return False
        else:
            return True

    def func_parameter_is_candidate(self, row):
        if self.func_parameter_not_on_blacklist(row):
            if self.filter_by_module and not self.api_candidate_is_in_fixed_module(row):
                return False
            return self.func_parameter_has_non_trivial_parameter(row)
        else:
            return False

    def collect_internal_function_parameters(self):
        self.project_logger.info("==> Stage 3: Collecting internal function parameters...")

        # 1. Invoke CodeQL to extract the internal function parameters
        if not os.path.exists(self.func_param_path) or self.overwrite or self.overwrite_func_param_candidates:
            self.project_logger.info("  ==> Extracting all function parameters by running CodeQL... ", no_new_line=True)
            self.run_simple_codeql_query("fetch_func_params", self.func_param_path)
            self.project_logger.print("Done.")
        else:
            self.project_logger.info("  ==> Existing function parameter file found. Skipping running CodeQL...")

        # 2. Filter it to get function parameter source candidates
        if not os.path.exists(self.source_func_param_candidates_path) or self.overwrite or self.overwrite_func_param_candidates:
            func_param_candidates = pd.read_csv(self.func_param_path, keep_default_na=False)
            num_internal_apis = len(func_param_candidates)

            # 3. Filter the APIs by internal
            func_param_candidates = self.keep_internal_packages(func_param_candidates)
            possible_func_param = func_param_candidates.apply(lambda row: self.func_parameter_is_candidate(row), axis=1)
            func_param_candidates = func_param_candidates[possible_func_param]

            # 4. Keep only the relevant fields for candidates
            func_param_candidates = func_param_candidates[["package", "clazz", "func", "full_signature", "doc"]]
            num_candidates = len(func_param_candidates)

            # 5. Dump the func param candidates
            self.project_logger.info(f"  ==> #Relevant APIs: {num_internal_apis}, #Filtered Candidates: {num_candidates}")
            self.project_logger.info("  ==> Dumping filtered function parameter candidates...")
            func_param_candidates.to_csv(self.source_func_param_candidates_path, index=False, header=True, sep=",", encoding="utf-8")
        else:
            self.project_logger.info("  ==> Existing source function parameter candidates file found. Skipping filtering candidates...")

    def read_methods_from_csv(self,file_path):
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

    def process_single_batch(self,batch_data):
        """处理单个批次的LLM分析（供多线程调用）"""
        batch_num, current_batch, start_idx, total_batches = batch_data
        print(f"开始处理第 {batch_num + 1}/{total_batches} 批...")

        # 构建当前批次的方法列表字符串
        method_list_str = "\n\n".join([
            f"Method {i + start_idx}:\n{method['info']}" 
            for i, method in enumerate(current_batch)
        ])

        # 构建提示
        prompt = [
            {"role": "system", "content": METHOD_ANALYSIS_SYSTEM_PROMPT},
            {"role": "user", "content": METHOD_ANALYSIS_USER_PROMPT.format(method_list=method_list_str)}
        ]
        client = OpenAI(
            api_key="sk-T1Vt6PLIOoBll7c2CkCsNOqtqB6rsdLcdcfrUyiXcOZOYDAD",
            base_url="https://api.chatanywhere.org/v1"
        )

        try:
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=prompt,
                temperature=0.3,
                response_format={"type": "json_object"}
            )
            result = json.loads(response.choices[0].message.content)
            print(f"第 {batch_num + 1}/{total_batches} 批处理完成")
            return result.get('analyses', []) if result else []
        
        except Exception as e:
            print(f"第 {batch_num + 1}/{total_batches} 批处理失败: {str(e)}")
            return []

    def write_analyzed_csv(self,methods,fieldnames):
        """将包含分析结果的数据写入新CSV文件"""
        new_fieldnames = fieldnames + ['analysis'] if fieldnames else ['analysis']

        with open(self.analysed_func_params_path, mode='w', encoding='utf-8', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=new_fieldnames)
            writer.writeheader()

            for method in methods:
                new_row = method['row'].copy()
                new_row['analysis'] = method.get('analysis', 'No analysis available')
                writer.writerow(new_row)

    def analyze_internal_function_parameters(self, batch_size=40,MAX_WORKERS = 5):
        self.project_logger.info("==> Stage 4: analyze internal function parameters...")
        if not self.analysis:
            self.project_logger.info("==>No need for analysis， skip this step.")
        else:
            if not os.path.exists(self.analysed_func_params_path) or self.overwrite or self.overwrite_analyze_func:
                """主函数：使用多线程并行处理批次分析"""
                print(f"从 {self.source_func_param_candidates_path} 读取方法数据...")
                methods, fieldnames = self.read_methods_from_csv(self.source_func_param_candidates_path)
                if not methods:
                    print("没有找到方法数据，程序退出。")
                    new_fieldnames = fieldnames + ['analysis'] if fieldnames else ['analysis']
                    with open(self.analysed_func_params_path, mode='w', encoding='utf-8', newline='') as file:
                        writer = csv.DictWriter(file, fieldnames=new_fieldnames)
                        writer.writeheader()
                    return

                total_methods = len(methods)
                total_batches = (total_methods + batch_size - 1) // batch_size
                print(f"找到 {total_methods} 个方法，分为 {total_batches} 批，使用 {MAX_WORKERS} 个线程并行处理...")

                # 准备批次数据
                batch_tasks = []
                for batch_num in range(total_batches):
                    start_idx = batch_num * batch_size
                    end_idx = min((batch_num + 1) * batch_size, total_methods)
                    current_batch = methods[start_idx:end_idx]
                    batch_tasks.append((batch_num, current_batch, start_idx, total_batches))

                # 多线程并行处理所有批次
                all_analysis_results = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    # 提交所有批次任务并获取结果
                    futures = [executor.submit(self.process_single_batch, task) for task in batch_tasks]
                    
                    # 收集所有结果
                    for future in concurrent.futures.as_completed(futures):
                        batch_results = future.result()
                        all_analysis_results.extend(batch_results)

                # 合并分析结果
                if all_analysis_results:
                    for result in all_analysis_results:
                        index = result['method_index']
                        if 0 <= index < len(methods):
                            methods[index]['analysis'] = result.get('natural_language_analysis', 'No analysis available')

                print(f"将分析结果写入 {self.analysed_func_params_path}...")
                self.write_analyzed_csv(methods, fieldnames)
                print("所有处理完成！")
            else:
                self.project_logger.info("  ==> Existing analyzed Funcs file found. Skipping analyze Funcs...")
    def load_cached_llm_labeled_apis(self):
        if os.path.exists(self.api_labels_cache_path):
            return json.load(open(self.api_labels_cache_path))
        else:
            return []

    def filter_to_query_apis_with_cache(self, candidates):
        """
        :param candidates, a list of the following [(<package>, <class>, <method>, <signature>), ...]
        """
        llm_results = self.load_cached_llm_labeled_apis()
        cached_apis = set([(item["package"], item["class"], item["method"], item["signature"]) for item in llm_results])
        # remaining_apis = sorted(list(set(candidates).difference(cached_apis)))
        # 只取前四个元素用于比较
        remaining_apis = sorted([item for item in candidates if (item[0], item[1], item[2], item[3]) not in cached_apis])
        return remaining_apis

    def merge_llm_labeled_apis_and_cache(self, candidates, new_llm_result):
        cached_result = self.load_cached_llm_labeled_apis()
        cached_mapping = {",".join([item["package"], item["class"], item["method"], item["signature"]]): item for item in cached_result}
        new_llm_mapping = {",".join([item["package"], item["class"], item["method"], item["signature"]]): item for item in new_llm_result}

        result = []
        for item in candidates:
            item_key = ",".join(item[:4])
            if item_key in new_llm_mapping:
                result.append(new_llm_mapping[item_key])
            elif item_key in cached_mapping:
                if cached_mapping[item_key].get("type", "") != "none":
                    copy_of_cached_item = {k: v for (k, v) in cached_mapping[item_key].items()}
                    result.append(copy_of_cached_item)
        return result

    def cache_llm_results(self, candidates, new_llm_result):
        if os.path.exists(self.api_labels_cache_path):
            try:
                cache = json.load(open(self.api_labels_cache_path))
            except json.JSONDecodeError as e:
                self.project_logger.error(f"Error when loading cache: {self.api_labels_cache_path}\n{e}"); exit(1)
        else:
            cache = []
        cached_apis = {(item["package"], item["class"], item["method"], item["signature"]): item for item in cache}
        llm_returned_apis = {(item["package"], item["class"], item["method"], item["signature"]): item for item in new_llm_result}
        for item in candidates:
            key = item[:4]  # 只取前四个元素作为key
            if key in cached_apis:
                if key in llm_returned_apis:
                    cached_apis[key]["type"] = llm_returned_apis[key].get("type", "none")
                else:
                    cached_apis[key]["type"] = "none"
            else:
                if key in llm_returned_apis:
                    to_cache_obj = {k: v for (k, v) in llm_returned_apis[key].items()}
                else:
                    to_cache_obj = {"package": key[0], "class": key[1], "method": key[2], "signature": key[3], "type": "none"}
                cached_apis[key] = to_cache_obj
        reload_cache = [cached_apis[item] for item in sorted(cached_apis.keys())]
        json.dump(reload_cache, open(self.api_labels_cache_path, "w"), indent=2)
        #存储的是结果的json列表

    def parse_json(self, json_str):
        try:
            #print("try 1", json_str)
            import re
            json_str = json_str.replace("\\n", "").replace("\\\n", "")
            json_str = re.sub("//.*", "", json_str)
            json_str = re.sub("\"\"", "\"", json_str)
            json_str = re.findall("\[[\s\S]*\]", json_str)[0]
            #json_str = re.sub(r"\\n", "", json_str)
            result = json.loads(json_str)
            if type(result) == list:
                return result
            else:
                return []
        except Exception as e:
            print(e)
            try:
                self.project_logger.error("Error parsing JSON 1. Trying list parsing")
                results = re.findall(r"{[^}]*}", json_str)
                results = [json.loads(r.strip()) for r in results]
                return results
            except Exception as e:
                print(e)
                self.project_logger.error("Error parsing JSON 2")
                self.project_logger.error(json_str)
        return []

    def query_gpt_for_api_src_tp_sink_batched(self):
        self.project_logger.info("==> Stage 5: Querying GPT for source/taint-prop/sink APIs...")

        # Check if there is labelled sink/source/propagataint-propagator
        if not os.path.exists(self.llm_labelled_source_apis_path) or self.overwrite or self.overwrite_labelled_apis:
            # 1. Load the candidates
            if self.analysis:
                self.project_logger.info("API is already analysed. Loading candidates from analysed APIs CSV...")
                candidates_csv = pd.read_csv(self.analysed_apis_csv_path, keep_default_na=False)
                candidates = [(row["package"], row["clazz"], row["func"], row["full_signature"],row["analysis"]) for (_, row) in candidates_csv.iterrows()]
            else:
                self.project_logger.info("API is not analysed. Loading candidates from candidate APIs CSV...")
                candidates_csv = pd.read_csv(self.candidate_apis_csv_path, keep_default_na=False)
                candidates = [(row["package"], row["clazz"], row["func"], row["full_signature"]) for (_, row) in candidates_csv.iterrows()]
            
            # 6. If the candidates are too many, exit
            if self.skip_huge_project and len(candidates) > self.skip_huge_project_num_apis_threshold:
                self.project_logger.info("  ==> Skipping project due to it being too large...")
                exit(0)

            # 2. Load the cache (if needed), and eliminate candidates for querying
            if self.overwrite_llm_cache:
                to_query_candidates = candidates
            else:
                to_query_candidates = self.filter_to_query_apis_with_cache(candidates)
                # to_query_candidates = candidates
            num_cached_candidates = len(candidates) - len(to_query_candidates)
            self.project_logger.info(f"  ==> Querying GPT... #Candidates: {len(candidates)}, #To Query APIs: {len(to_query_candidates)}, #Cached: {num_cached_candidates}")

            # 3. Setup LLMs and relevant queries
            #model = LLM.get_llm(model_name=self.llm, logger=self.project_logger, kwargs={"seed": self.seed, "max_new_tokens": 1024})
            system_prompt = API_LABELLING_SYSTEM_PROMPT
            cwe_description = QUERIES[self.query]["prompts"]["desc"]
            cwe_long_description = QUERIES[self.query]["prompts"]["long_desc"]
            cwe_examples = json.dumps(QUERIES[self.query]["prompts"]["examples"], indent=2)

            # 4. Setup dispatch function. This function will be invoked for each batch, where i = 0, batch_size, 2 * batch_size, ...
            def process_candidate_batch(i):
                # 4.1. Get the batch of to query candidates
                batch = to_query_candidates[i:i + self.label_api_batch_size]
                api_list_text = "\n".join([",".join(row) for row in batch])

                # 4.2. Build the user prompt and dump it
                user_prompt = API_LABELLING_USER_PROMPT.format(
                    cwe_description=cwe_description,
                    cwe_id=self.cwe_id,
                    cwe_long_description=cwe_long_description,
                    cwe_examples=cwe_examples,
                    methods=api_list_text)
                with open(f"{self.label_api_log_path}/raw_user_prompt_{i}.txt", "w") as f:
                    f.write(user_prompt + "\n")

                return [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ]

                # 4.4. Parse the GPT result
                #json_result = self.parse_json(result)
                #return json_result

            # 5. Iterate through all batches and generate result
            args = range(0, len(to_query_candidates), self.label_api_batch_size)
            indiv_prompts = [process_candidate_batch(i) for i in args]
            indiv_results = []
            responses = self.get_model().predict(indiv_prompts, batch_size=self.num_threads)
            for i, response in zip(args, responses):
                json_result = self.parse_json(response)
                with open(f"{self.label_api_log_path}/raw_llm_response_{i}.txt", "w") as f:
                    f.write(str(response) + "\n")
                indiv_results.append(json_result)

            # 6. Merge all the results
            merged_llm_results = []
            for indiv_result in indiv_results:
                merged_llm_results.extend(indiv_result)
            merged_llm_results=self.filter_invalid_entries(merged_llm_results)
            # 7. Save the result for this project

            merged_overall_results = self.merge_llm_labeled_apis_and_cache(candidates, merged_llm_results)#结果是llm的所有结果和缓存中的非none结果的合并
            # merged_overall_results = merged_llm_results
            sources = [r for r in merged_overall_results if r.get("type", "") == "source"]
            taint_props = [r for r in merged_overall_results if r.get("type", "") == "taint-propagator"]
            sinks = [r for r in merged_overall_results if r.get("type", "") == "sink"]
            self.project_logger.info(f"  ==> #APIs Labelled by LLM: {len(merged_overall_results)}, #Source: {len(sources)}, #Sink: {len(sinks)}, #Taint Propagators: {len(taint_props)}")
            if not self.test_run:
                json.dump(sources, open(self.llm_labelled_source_apis_path, "w"), indent=2)
                json.dump(taint_props, open(self.llm_labelled_taint_prop_apis_path, "w"), indent=2)
                json.dump(sinks, open(self.llm_labelled_sink_apis_path, "w"), indent=2)

            # 8. Save the results for common cache
            if not self.test_run:
                self.cache_llm_results(candidates, merged_overall_results)
        else:
            self.project_logger.info("  ==> Existing labelled source/taint-prop/sink APIs found. Skipping querying GPT...")

    def first_project_description_paragraph(self, readme_lines):
        filtered_lines = []
        prev_line_is_empty = True
        for line in readme_lines:
            if len(filtered_lines) > 10:
                break
            if line.strip() == "":
                if prev_line_is_empty:
                    continue
                else:
                    filtered_lines.append("")
                    prev_line_is_empty = True
            elif line.strip()[0].isalpha():
                filtered_lines.append(line.strip())
            else:
                if prev_line_is_empty:
                    continue
                else:
                    filtered_lines.append("")
                    prev_line_is_empty = True
        return "\n".join(filtered_lines)

    def fetch_project_description_from_commit_readme(self, commit_link):
        # Try for each possible readme file
        for possible_readme_file_name in ["README.md", "README.adoc", "README", "readme.md", "readme"]:
            link = commit_link + "/" + possible_readme_file_name
            self.project_logger.info(f"  ==> Attempting to fetch project readme from {link}...")
            try:
                response = requests.get(link)
                if response.status_code == 200:
                    self.project_logger.info(f"  ==> Success!")
                    lines = response.text.split('\n')
                    first_markdown_paragraph = self.first_project_description_paragraph(lines)

                    # Success. Dump the readme and the head
                    with open(f"{self.label_func_params_log_path}/readme.txt", "w") as f:
                        f.write("\n".join(lines))
                    with open(f"{self.label_func_params_log_path}/readme_head.txt", "w") as f:
                        f.write(first_markdown_paragraph)

                    return first_markdown_paragraph
                else:
                    self.project_logger.info(f"  ==> Fail")
            except Exception as e:
                self.project_logger.info(f"  ==> Fail with error: {e}")

    def fetch_project_description_from_readme(self):
        readme_head_txt_path = f"{self.label_func_params_log_path}/readme_head.txt"
        if os.path.exists(readme_head_txt_path) and not self.overwrite:
            self.project_logger.info("  ==> Found fetched readme. Skipping fetch project description...")
            return "".join(list(open(readme_head_txt_path)))
        else:
            # There has to be some commit associated with this CVE
            if len(self.cve_fixing_commits) == 0:
                self.project_logger.error("  ==> No fixing commits found for project; aborting"); return

            # Get repository information from the CSV data
            github_username = self.project_cve_with_commit_info["github_username"]
            github_repo = self.project_cve_with_commit_info["github_repository_name"]
            repo_base = f"https://raw.githubusercontent.com/{github_username}/{github_repo}"

            # Iterate through all commit hashes
            for commit_hash in self.cve_fixing_commits:
                base_link = f"{repo_base}/{commit_hash}"
                paragraph = self.fetch_project_description_from_commit_readme(base_link)
                if paragraph is not None:
                    return paragraph

            # If not successful, fallback to master branch
            base_link = f"{repo_base}/master"
            paragraph = self.fetch_project_description_from_commit_readme(base_link)
            if paragraph is not None:
                return paragraph

            # At this stage, it is failed
            self.project_logger.error(f"  ==> Cannot pull project readme. Aborting..."); return

    def extract_doc(self, doc_str):
        if doc_str is None:
            return ""
        elif len(doc_str) <= MAX_DOC_LENGTH:
            return doc_str
        else:
            return doc_str[:MAX_DOC_LENGTH] + "..."

    def fetch_func_param_src_candidates(self):
        if self.analysis:
            self.project_logger.info("Fetching source function parameter candidates from analysed CSV...")
            candidates_csv = pd.read_csv(self.analysed_func_params_path, keep_default_na=False)
            # Do deduplication
            dedup_map = {}
            for (_, row) in candidates_csv.iterrows():
                key = (row["package"], row["clazz"], row["func"])
                if key not in dedup_map:
                    dedup_map[key] = row
                else:
                    if row["doc"] != "":
                        dedup_map[key] = row
                    elif len(row["full_signature"]) > len(dedup_map[key]["full_signature"]):
                        dedup_map[key] = row

            # Add doc into the candidates
            # candidates = [(key[0], key[1], key[2], row["full_signature"], self.extract_doc(row["doc"])) for (key, row) in dedup_map.items()]
            candidates = [(key[0], key[1], key[2], row["full_signature"], self.extract_doc(row["doc"]),row["analysis"]) for (key, row) in dedup_map.items()]
            # Count the number of functions with documentations
            num_with_docs = len([() for cand in candidates if cand[4] != ""])
            self.project_logger.info(f"  ==> #Candidate functions with source param: {len(candidates_csv)}; after deduplication: {len(candidates)}; with documentations: {num_with_docs}. Querying LLM...")

            # Return
            return candidates
        else:
            self.project_logger.info("Fetching source function parameter candidates from candidates CSV...")
            candidates_csv = pd.read_csv(self.source_func_param_candidates_path, keep_default_na=False)
            # Do deduplication
            dedup_map = {}
            for (_, row) in candidates_csv.iterrows():
                key = (row["package"], row["clazz"], row["func"])
                if key not in dedup_map:
                    dedup_map[key] = row
                else:
                    if row["doc"] != "":
                        dedup_map[key] = row
                    elif len(row["full_signature"]) > len(dedup_map[key]["full_signature"]):
                        dedup_map[key] = row

            # Add doc into the candidates
            candidates = [(key[0], key[1], key[2], row["full_signature"], self.extract_doc(row["doc"])) for (key, row) in dedup_map.items()]
            # Count the number of functions with documentations
            num_with_docs = len([() for cand in candidates if cand[4] != ""])
            self.project_logger.info(f"  ==> #Candidate functions with source param: {len(candidates_csv)}; after deduplication: {len(candidates)}; with documentations: {num_with_docs}. Querying LLM...")

            # Return
            return candidates

    def query_gpt_for_func_param_src(self):
        self.project_logger.info("==> Stage 6: Querying GPT for source function parameters...")
        if not os.path.exists(self.llm_labelled_source_func_params_path) or self.overwrite or self.overwrite_labelled_func_param:
            # 1. Get LLM and fetch information used for prompt
            system_prompt = FUNC_PARAM_LABELLING_SYSTEM_PROMPT
            proj_description = self.fetch_project_description_from_readme()
            proj_username = self.project_name.split("_")[0]
            proj_name = self.project_name.split("_")[2]

            # 2. Get LLM
            #model = LLM.get_llm(model_name=self.llm, logger=self.project_logger, kwargs={"seed": self.seed, "max_new_tokens": 1024})

            # 3. Load the candidates
            candidates = self.fetch_func_param_src_candidates()

            # 4. Setup dispatch function. This function will be invoked for each batch, where i = 0, batch_size, 2 * batch_size, ...
            def process_candidate_batch(i):
                # 4.1. Get the batch of to query candidates
                batch = candidates[i:i + self.label_func_param_batch_size]
                if not self.analysis:
                    api_list_text = "\n".join([",".join([row[0], row[1], row[3], row[4]]) for row in batch])
                else:
                    api_list_text = "\n".join([",".join([row[0], row[1], row[3], row[4], row[5]]) for row in batch])

                # 4.2. Build the user prompt and dump it
                user_prompt = FUNC_PARAM_LABELLING_USER_PROMPT.format(
                    project_username=proj_username,
                    project_name=proj_name,
                    project_readme_summary=proj_description,
                    methods=api_list_text)
                with open(f"{self.label_func_params_log_path}/raw_user_prompt_{i}.txt", "w") as f:
                    f.write(user_prompt + "\n")


                return [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ]

            # 5. Actually dispatch the tasks
            # args = range(0, len(candidates), self.label_func_param_batch_size)
            # indiv_results = thread_map(process_candidate_batch, args, max_workers=self.num_threads)

            args = range(0, len(candidates), self.label_func_param_batch_size)
            indiv_prompts = [process_candidate_batch(i) for i in args]
            indiv_results = []
            responses = self.get_model().predict(indiv_prompts, batch_size=self.num_threads)
            for i, response in zip(args, responses):
                json_result = self.parse_json(response)
                with open(f"{self.label_func_params_log_path}/raw_llm_response_{i}.txt", "w") as f:
                        f.write(response + "\n")
                indiv_results.append(json_result)

            # 6. Merge all the results
            merged_llm_results = []
            for indiv_result in indiv_results:
                merged_llm_results.extend(indiv_result)

            # 7. Save the result for this project
            self.project_logger.info(f"  ==> Finished querying LLM. #Function with source param: {len(merged_llm_results)}")
            if not self.test_run:
                json.dump(merged_llm_results, open(self.llm_labelled_source_func_params_path, "w"), indent=2)
        else:
            self.project_logger.info(f"  ==> Found labelled source function parameters. Skipping...")

    def not_none(self, d, keys):
        return isinstance(d, dict) and all([d.get(k, None) for k in keys])

    def filter_invalid_entries(self, api_list):
        return [api for api in api_list if self.not_none(api, ["method", "class", "package","signature"])]

    def label_transmit_with_rag(self):
        self.project_logger.info("==> Stage 8: RAG for label transfer...")
        if not self.analysis:
            self.project_logger.info("==>No need for analysis， skip this step.")
            return
        else:
            print("=== 开始API标签传播流程 ===")
            if not self.skip_api_transmit:
                self.propagate_api_labels()
            print("\n=== 开始函数参数标签传播流程 ===")
            if not self.skip_func_transmit:
                self.propagate_func_param_labels()
            return

    # ------------------------------
    # API标签传播相关方法
    # ------------------------------
    def load_analysed_apis(self):
        """加载分析过的API数据并构建向量知识库"""
        print(f"加载并处理API数据: {self.analysed_apis_csv_path}")

        if not os.path.exists(self.analysed_apis_csv_path):
            print(f"API数据文件不存在: {self.analysed_apis_csv_path}")
            return

        with open(self.analysed_apis_csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # 对analysis文本进行向量化
                analysis_text = row['analysis']
                embedding = self.embedding_model.encode(analysis_text)
                # 存储函数信息和向量
                function_info = {
                    'package': row['package'],
                    'class': row['clazz'],
                    'method': row['func'],
                    'signature': row['full_signature'],
                    'embedding': embedding
                }
                self.vector_db_apis.append(function_info)
        
        print(f"API向量知识库构建完成，共包含 {len(self.vector_db_apis)} 个函数")

    def load_labelled_apis(self):
        """加载已标记的API函数"""
        # 加载源函数
        if os.path.exists(self.llm_labelled_source_apis_path):
            with open(self.llm_labelled_source_apis_path, 'r', encoding='utf-8') as f:
                self.labelled_apis['source'] = json.load(f)
            print(f"加载源函数 {len(self.labelled_apis['source'])} 个")
        
        # 加载sink函数
        if os.path.exists(self.llm_labelled_sink_apis_path):
            with open(self.llm_labelled_sink_apis_path, 'r', encoding='utf-8') as f:
                self.labelled_apis['sink'] = json.load(f)
            print(f"加载sink函数 {len(self.labelled_apis['sink'])} 个")
        
        # 加载污点传播函数
        if os.path.exists(self.llm_labelled_taint_prop_apis_path):
            with open(self.llm_labelled_taint_prop_apis_path, 'r', encoding='utf-8') as f:
                self.labelled_apis['taint-propagator'] = json.load(f)
            print(f"加载污点传播函数 {len(self.labelled_apis['taint-propagator'])} 个")

    def find_unlabelled_apis(self):
        """找出所有未标记的API函数"""
        # 创建已标记函数的唯一标识符集合
        labelled_ids = set()
        
        for label_type, functions in self.labelled_apis.items():
            for func in functions:
                func_id = (func['package'], func['class'], func['method'], func['signature'])
                labelled_ids.add(func_id)
        
        # 筛选未标记的函数
        unlabelled = []
        for func in self.vector_db_apis:
            func_id = (func['package'], func['class'], func['method'], func['signature'])
            if func_id not in labelled_ids:
                unlabelled.append(func)
        
        print(f"找到 {len(unlabelled)} 个未标记的API函数")
        return unlabelled

    def _save_propagated_apis(self, propagated_labels):
        """保存传播后的API标签到对应的JSON文件"""
        # 保存source函数
        if propagated_labels['source']:
            self._save_propagated_labels(
                propagated_labels['source'], 
                self.llm_labelled_source_apis_path,
                'source'
            )
        
        # 保存sink函数
        if propagated_labels['sink']:
            self._save_propagated_labels(
                propagated_labels['sink'], 
                self.llm_labelled_sink_apis_path,
                'sink'
            )
        
        # 保存taint-propagator函数
        if propagated_labels['taint-propagator']:
            self._save_propagated_labels(
                propagated_labels['taint-propagator'], 
                self.llm_labelled_taint_prop_apis_path,
                'taint-propagator'
            )

    def propagate_api_labels(self):
        """执行API标签传播"""
        # 确保数据已加载
        if not self.vector_db_apis:
            self.load_analysed_apis()
        
        if not any(self.labelled_apis.values()):
            self.load_labelled_apis()
        
        # 找到未标记的函数
        unlabelled = self.find_unlabelled_apis()
        if not unlabelled:
            print("没有未标记的API函数需要处理")
            return
        
        propagated = {
            'source': [],
            'sink': [],
            'taint-propagator': []
        }
        
        print(f"开始API标签传播，共处理 {len(unlabelled)} 个函数")
        
        for i, func in enumerate(unlabelled, 1):
            if i % 10 == 0:
                print(f"已处理 {i}/{len(unlabelled)} 个API函数")
            # 找到最相似的已标记函数
            first_fitted_similar = self._find_fitted_similar(
                func, self.labelled_apis, self.vector_db_apis, has_label_type=True)
            if not first_fitted_similar:
                continue
            # 创建新的标签条目
            new_entry = {
                'package': func['package'],
                'class': func['class'],
                'method': func['method'],
                'signature': func['signature'],
                'sink_args': [],
                'type': first_fitted_similar['label_type'],
            }
            # 添加到相应的标签组
            propagated[first_fitted_similar['label_type']].append(new_entry)
        # 统计结果
        total = sum(len(v) for v in propagated.values())
        print(f"API标签传播完成，共为 {total} 个函数自动标记标签")
        
        # 保存结果
        self._save_propagated_apis(propagated)

    # ------------------------------
    # 函数参数标签传播相关方法
    # ------------------------------
    def load_analysed_func_params(self):
        """加载分析过的函数参数数据并构建向量知识库"""
        print(f"加载并处理函数参数数据: {self.analysed_func_params_path}")
        
        if not os.path.exists(self.analysed_func_params_path):
            print(f"函数参数数据文件不存在: {self.analysed_func_params_path}")
            return
            
        with open(self.analysed_func_params_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # 对analysis文本进行向量化
                analysis_text = row['analysis']
                embedding = self.embedding_model.encode(analysis_text)
                
                # 提取函数参数
                params = self._extract_parameters(row['full_signature'])
                
                # 存储函数信息和向量，不包含doc列
                function_info = {
                    'package': row['package'],
                    'class': row['clazz'],
                    'method': row['func'],
                    'signature': row['full_signature'],
                    'embedding': embedding,
                    'parameters': params
                }
                self.vector_db_func_params.append(function_info)
        print(f"函数参数向量知识库构建完成，共包含 {len(self.vector_db_func_params)} 个函数")

    def load_labelled_func_params(self):
        """加载已标记的函数参数"""
        if os.path.exists(self.llm_labelled_source_func_params_path):
            with open(self.llm_labelled_source_func_params_path, 'r', encoding='utf-8') as f:
                self.labelled_func_params = json.load(f)
            print(f"加载已标记的函数参数 {len(self.labelled_func_params)} 个")
        else:
            print(f"未找到已标记的函数参数文件: {self.llm_labelled_source_func_params_path}")
            self.labelled_func_params = []

    def find_unlabelled_func_params(self):
        """找出所有未标记的函数参数"""
        # 创建已标记函数的唯一标识符集合
        labelled_ids = set()
        
        for func in self.labelled_func_params:
            func_id = (func['package'], func['class'], func['method'], func['signature'])
            labelled_ids.add(func_id)
        
        # 筛选未标记的函数
        unlabelled = []
        for func in self.vector_db_func_params:
            func_id = (func['package'], func['class'], func['method'], func['signature'])
            if func_id not in labelled_ids:
                unlabelled.append(func)
        
        print(f"找到 {len(unlabelled)} 个未标记的函数参数")
        return unlabelled

    def _save_propagated_func_params(self, propagated_labels):
        """保存传播后的函数参数标签到对应的JSON文件"""
        self._save_propagated_labels(
            propagated_labels, 
            self.llm_labelled_source_func_params_path,
            'source'
        )

    def _extract_parameters(self, signature):
        """从函数签名中提取参数名"""
        if '(' not in signature or ')' not in signature:
            return []
            
        params_part = signature.split('(')[1].split(')')[0]
        if not params_part:
            return []
            
        # 分割参数并提取参数名（假设格式为"类型 参数名"）
        params = []
        for param in params_part.split(','):
            param = param.strip()
            if param:
                # 取最后一个空格后的部分作为参数名
                param_name = param.split()[-1]
                params.append(param_name)
                
        return params

    def propagate_func_param_labels(self):
        """执行函数参数标签传播"""
        # 确保数据已加载
        if not self.vector_db_func_params:
            self.load_analysed_func_params()
        
        if not self.labelled_func_params:
            self.load_labelled_func_params()
        
        # 找到未标记的函数参数
        unlabelled = self.find_unlabelled_func_params()
        if not unlabelled:
            print("没有未标记的函数参数需要处理")
            return
        
        propagated = []
        
        print(f"开始函数参数标签传播，共处理 {len(unlabelled)} 个函数")
        
        for i, func in enumerate(unlabelled, 1):
            if i % 10 == 0:
                print(f"已处理 {i}/{len(unlabelled)} 个函数参数")
                
            # 找到最相似的已标记函数
            first_fitted_similar = self._find_fitted_similar(func, self.labelled_func_params, self.vector_db_func_params, has_label_type=False) 
            if not first_fitted_similar:
                continue
            # 创建新的标签条目，tainted_input为新标记函数的所有形参
            new_entry = {
                'package': func['package'],
                'class': func['class'],
                'method': func['method'],
                'signature': func['signature'],
                'tainted_input': func['parameters'],  # 使用解析出的所有参数
            }
            propagated.append(new_entry)
        
        print(f"函数参数标签传播完成，共为 {len(propagated)} 个函数自动标记标签")
        
        # 保存结果
        self._save_propagated_func_params(propagated)

    def _find_fitted_similar(self, target_func, labelled_items, vector_db, has_label_type=False):
        """
        找到第一个超过阈值的已标记项
        
        Args:
            target_func: 目标未标记函数
            labelled_items: 已标记的函数列表
            vector_db: 向量数据库
            has_label_type: 是否包含标签类型（API场景为True，函数参数场景为False）
            
        Returns:
            第一个超过阈值的函数信息，包含相似度；若无则返回None
        """
        labelled_with_embeddings = []
        
        # 根据是否需要标签类型处理不同格式的输入
        if has_label_type:
            # API场景：labelled_items是包含label_type的字典
            for label_type, functions in labelled_items.items():
                for func in functions:
                    match = self._find_matching_function(func, vector_db)
                    if match:
                        labelled_with_embeddings.append({
                            'function': func,
                            'label_type': label_type,
                            'embedding': match['embedding']
                        })
        else:
            # 函数参数场景：labelled_items是简单列表
            for func in labelled_items:
                match = self._find_matching_function(func, vector_db)
                if match:
                    labelled_with_embeddings.append({
                        'function': func,
                        'embedding': match['embedding']
                    })
        
        if not labelled_with_embeddings:
            return None
        
        # 计算第一个相似的项
        target_embedding = target_func['embedding'].reshape(1, -1)

        for item in labelled_with_embeddings:
            emb = item['embedding'].reshape(1, -1)
            similarity = cosine_similarity(target_embedding, emb)[0][0]
            if similarity > self.similarity_threshold:
                first_fitted_similar = {
                    'function': item['function'],
                }
                # 如果有标签类型，添加到结果中
                if has_label_type:
                    first_fitted_similar['label_type'] = item['label_type']
                break

        return first_fitted_similar

    def _find_matching_function(self, func, vector_db):
        """辅助方法：在向量库中找到匹配的函数"""
        return next((f for f in vector_db 
                    if f['package'] == func['package'] 
                    and f['class'] == func['class']
                    and f['method'] == func['method']
                    and f['signature'] == func['signature']), None)

    def _save_propagated_labels(self, propagated, file_path, label_type):
        """通用的保存传播标签的方法"""
        if not propagated:
            return
            
        # 加载现有数据
        existing = []
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                existing = json.load(f)
        
        # 合并并去重
        combined = existing + propagated
        unique_combined = self._remove_duplicates(combined)
        
        # 保存结果
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(unique_combined, f, indent=2, ensure_ascii=False)
        
        print(f"已将 {len(propagated)} 个{label_type}函数标记追加到 {file_path}")

    def _remove_duplicates(self, functions):
        """移除重复的函数条目"""
        seen = set()
        unique_functions = []
        
        for func in functions:
            func_id = (func['package'], func['class'], func['method'], func['signature'])
            if func_id not in seen:
                seen.add(func_id)
                unique_functions.append(func)
        
        return unique_functions

    def build_source_qll_with_enumeration(self):
        source_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_source_apis_path)))
        source_api_entries = [
            QL_METHOD_CALL_SOURCE_BODY_ENTRY.format( #查询所有调用了该method的地方
                method=api["method"],
                package=api["package"],
                clazz=api["class"],
            ) for api in source_apis
        ]
        source_params = self.filter_invalid_entries(json.load(open(self.llm_labelled_source_func_params_path)))
        source_params_entries = [
            QL_FUNC_PARAM_SOURCE_ENTRY.format( #查询在指定方法中的所有参数
                method=param_func["method"],
                package=param_func["package"],
                clazz=param_func["class"],
                params=" or ".join([
                    QL_FUNC_PARAM_NAME_ENTRY.format(
                        arg_name=arg_name
                    ) for arg_name in param_func["tainted_input"]
                ]),
            )
            if isinstance(param_func, dict) and len(param_func.get("tainted_input", [])) > 0
            else "1 = 0"
            for param_func in source_params
        ]
        all_entries = source_api_entries + source_params_entries
        if len(all_entries) == 0:
            all_entries = ["1 = 0"]

        batch_size = 300 #source 每一批执行的ql查询条目
        if len(all_entries) > batch_size:
            num_batches = int(math.ceil(len(all_entries) / batch_size))
            body = " or\n".join([
                CALL_QL_SUBSET_PREDICATE.format(part_id=i, kind="Source", node="src")
                for i in range(num_batches)])
            additional = "\n\n".join([
                QL_SUBSET_PREDICATE.format(
                    part_id=i,
                    kind="Source",
                    node="src",
                    body=QL_BODY_OR_SEPARATOR.join(all_entries[i * batch_size : (i + 1) * batch_size]))
                for i in range(num_batches)
            ])
        else:
            body = QL_BODY_OR_SEPARATOR.join(all_entries)
            additional = ""

        my_source_content = QL_SOURCE_PREDICATE.format(body=body, additional=additional)#检测节点是不是被LLM标记的source节点
        return my_source_content

    def build_and_save_source_qll_with_enumeration(self):
        with open(self.source_qll_path, "w") as f:
            f.write(self.build_source_qll_with_enumeration())

    def build_and_save_source_qll_with_source_node(self):
        my_source_content = QL_SOURCE_PREDICATE.format(
            body=f"sourceNode(src, \"{self.project_name}\")")
        with open(self.source_qll_path, "w") as f:
            f.write(my_source_content)

    def build_taint_propagator_qll_with_enumeration(self):
        summary_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_taint_prop_apis_path)))

        if len(summary_apis) == 0 or self.no_summary_model:
            body = "1 = 0"
        else:
            body = QL_BODY_OR_SEPARATOR.join([
                QL_SUMMARY_BODY_ENTRY.format(
                    package=api["package"],
                    clazz=api["class"],
                    method=api["method"],
                ) for api in summary_apis
            ])
        my_summary_content = QL_STEP_PREDICATE.format(body=body)
        return my_summary_content

    def build_and_save_taint_propagator_qll_with_enumeration(self):
        with open(self.summary_qll_path, "w") as f:
            f.write(self.build_taint_propagator_qll_with_enumeration())

    def build_sink_qll_with_enumeration(self):
        sink_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_sink_apis_path)))
        if len(sink_apis) == 0:
            body = "1 = 0"
            additional = ""
        else:
            def sink_body_entry(api):
                if "sink_args" in api and \
                    any(
                        len(re.findall(r"[\S\s]*p([0-9]+)", str(sink_arg))) > 0 or str(sink_arg) == "this"
                        for sink_arg in api["sink_args"]
                    ):
                    return QL_SINK_BODY_ENTRY.format(
                        method=api["method"],
                        package=api["package"],
                        clazz=api["class"],
                        args=" or ".join([
                            QL_SINK_ARG_THIS_ENTRY if sink_arg == "this" else
                            QL_SINK_ARG_NAME_ENTRY.format(
                                arg_id=int(re.findall(r"[\S\s]*p([0-9]+)", sink_arg)[0]), # sink_arg will be `pX` where X is a number
                            )
                            for sink_arg in api["sink_args"]
                            if len(re.findall(r"[\S\s]*p([0-9]+)", str(sink_arg))) > 0 or str(sink_arg) == "this"
                        ])
                    )
                else:
                    return "1 = 0"

            def sink_body(apis):
                return QL_BODY_OR_SEPARATOR.join([sink_body_entry(api) for api in sink_apis])

            batch_size = 300
            if len(sink_apis) > batch_size:
                num_batches = int(math.ceil(len(sink_apis) / batch_size))
                body = " or\n".join([
                    CALL_QL_SUBSET_PREDICATE.format(part_id=i, kind="Sink", node="snk")
                    for i in range(num_batches)])
                additional = "\n\n".join([
                    QL_SUBSET_PREDICATE.format(
                        part_id=i,
                        kind="Sink",
                        node="snk",
                        body=sink_body(sink_apis[i * batch_size : (i + 1) * batch_size]))
                    for i in range(num_batches)
                ])
            else:
                body = sink_body(sink_apis)
                additional = ""
        my_sink_content = QL_SINK_PREDICATE.format(body=body, additional=additional)
        return my_sink_content

    def build_and_save_sink_qll_with_enumeration(self):
        with open(self.sink_qll_path, "w") as f:
            f.write(self.build_sink_qll_with_enumeration())

    def build_and_save_sink_qll_with_sink_node(self):
        my_sink_content = QL_SINK_PREDICATE.format(
            body=f"sinkNode(snk, \"{self.project_name}\")")
        with open(self.sink_qll_path, "w") as f:
            f.write(my_sink_content)

    def build_extension_yml(self):
        # First load labelled sources, sinks, and taint-propagators
        source_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_source_apis_path)))
        source_params = self.filter_invalid_entries(json.load(open(self.llm_labelled_source_func_params_path)))
        sink_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_sink_apis_path)))
        taint_prop_apis = self.filter_invalid_entries(json.load(open(self.llm_labelled_taint_prop_apis_path)))

        # Convert into entries
        source_api_entries = "\n".join([
            EXTENSION_SRC_SINK_YML_ENTRY.format(
                package=source_api["package"],
                clazz=source_api["class"],
                method=source_api["method"],
                access="ReturnValue",
                tag=self.project_name,
            ) for source_api in source_apis if isinstance(source_api, dict)
        ])
        source_params=[k for k in source_params if isinstance(k, dict)]
        source_func_parm_entries = "\n".join([
            EXTENSION_SRC_SINK_YML_ENTRY.format(
                package=source_func_param["package"],
                clazz=source_func_param["class"],
                method=source_func_param["method"],
                access=f"Parameter[{'this' if param_name == 'this' else param_name[1:]}]",
                tag=self.project_name,
            )
            for source_func_param in source_params
            for param_name in source_func_param.get("tainted_input", [])
        ])
        sink_api_entries = "\n".join([
            EXTENSION_SRC_SINK_YML_ENTRY.format(
                package=sink_api["package"],
                clazz=sink_api["class"],
                method=sink_api["method"],
                access="Argument[0..10]",
                tag=self.project_name,
            )
            for sink_api in sink_apis if isinstance(sink_api, dict)
            # for arg_name in sink_api["sink_args"]
        ])

        # Build the final yaml
        yml_content = EXTENSION_YML_TEMPLATE.format(
            sources="\n".join([source_api_entries, source_func_parm_entries]),
            sinks=sink_api_entries)

        return yml_content

    def build_and_save_extension_yml(self):
        with open(self.spec_yml_path, "w") as f:
            f.write(self.build_extension_yml())

    def build_project_specific_query(self):
        if self.test_run: return

        self.project_logger.info("==> Stage 8: Building project specific query...")

        self.project_logger.info("  ==> Building source query...")
        if self.use_exhaustive_qll:
            self.build_and_save_source_qll_with_enumeration()
        else:
            self.build_and_save_source_qll_with_source_node()

        self.project_logger.info("  ==> Building taint-propagator query...")
        self.build_and_save_taint_propagator_qll_with_enumeration()

        self.project_logger.info("  ==> Building sink query...")
        if self.use_exhaustive_qll:
            self.build_and_save_sink_qll_with_enumeration()
        else:
            self.build_and_save_sink_qll_with_sink_node()

        # NOT WORKING YAML
        self.project_logger.info("  ==> Building extension yml...")
        self.build_and_save_extension_yml()

    def find_vulnerability(self):
        self.project_logger.info("==> Stage 9: Finding vulnerabilities with CodeQL...")

        # Step 0: Check if result already exists
        if os.path.exists(self.query_output_result_sarif_path) and not self.overwrite and not self.overwrite_cwe_query_result:
            self.project_logger.info(f"  ==> Found existing {self.query} results; skipping...")
            return
        if self.test_run:
            self.project_logger.info(f"  ==> Test run; skipping...")
            return

        # Step 1: Copy all the query related
        self.project_logger.info("  ==> Copying custom queries...")
        codeql_query_dir = f"{CODEQL_CUSTOM_QUERY_DIR}/{self.project_name}/{self.query}/{self.run_id}"
        os.makedirs(codeql_query_dir, exist_ok=True)
        for q in QUERIES[self.query]["queries"]:
            shutil.copy(f"{THIS_SCRIPT_DIR}/{q}", f"{codeql_query_dir}/")
            self.project_logger.info(f"  ==> Copying {q}... Done!")

        # Step 2: Copy the generated source/sink/taint-prop qll files
        shutil.copy(self.source_qll_path, f"{codeql_query_dir}/")
        self.project_logger.info(f"  ==> Copying source predicate ({self.source_qll_path.split('/')[-1]})... Done!")
        shutil.copy(self.summary_qll_path, f"{codeql_query_dir}/")
        self.project_logger.info(f"  ==> Copying summary query wrapper ({self.summary_qll_path.split('/')[-1]})... Done!")
        shutil.copy(self.sink_qll_path, f"{codeql_query_dir}/")
        self.project_logger.info(f"  ==> Copying sink predicate ({self.sink_qll_path.split('/')[-1]})... Done!")

        # Step 3: Copy the spec yml file
        # NOT WORKING YAML
        self.project_logger.info(f"  ==> Copying project specific specifications ({self.spec_yml_path.split('/')[-1]})...")
        target_yml_spec_dir = f"{CODEQL_CUSTOM_YML_DIR}/{self.project_name}"
        os.makedirs(target_yml_spec_dir, exist_ok=True)
        target_yml_spec_path = f"{target_yml_spec_dir}/specs.model.yml"
        shutil.copy(self.spec_yml_path, target_yml_spec_path)

        # Step 4: Run codeql analyze and produce sarif and csv
        self.project_logger.info("  ==> Running CodeQL analysis...")
        query_filename = QUERIES[self.query]["queries"][0].split("/")[-1]
        to_run_query_full_path = f"{codeql_query_dir}/{query_filename}"
        sp.run([CODEQL, "database", "analyze", "--rerun", self.project_codeql_db_path, "--format=sarif-latest", f"--output={self.query_output_result_sarif_path}", to_run_query_full_path])
        if not os.path.exists(self.query_output_result_sarif_path):
            self.project_logger.error("  ==> Result SARIF not produced; aborting"); return
        sp.run([CODEQL, "database", "analyze", "--rerun", self.project_codeql_db_path, "--format=csv", f"--output={self.query_output_result_csv_path}", to_run_query_full_path])
        if not os.path.exists(self.query_output_result_csv_path):
            self.project_logger.error("  ==> Result CSV not produced; aborting"); return

    def extract_class_locations(self):
        if not os.path.exists(self.class_locs_path):
            self.project_logger.info(f"  ==> Class locations not found; running CodeQL query to extract...")
            self.run_simple_codeql_query("fetch_class_locs")

    def extract_func_locations(self):
        if not os.path.exists(self.func_locs_path):
            self.project_logger.info(f"  ==> Function locations not found; running CodeQL query to extract...")
            self.run_simple_codeql_query("fetch_func_locs")

    def extract_enclosing_decl_locs_map(self, decl_locs):
        """
        Extract enclosing declaration locations mapping from a pandas DataFrame

        :param decl_locs, a pandas DataFrame containing function or class locations
        :returns a mapping from file name to list of declarations defined in that file.
                 each declaration is a tuple (<decl_name>, <start_line>, <end_line>)
        """
        enclosing_decl_locs = {}
        for (i, row) in decl_locs.iterrows():
            if row["file"] not in enclosing_decl_locs:
                enclosing_decl_locs[row["file"]] = []
            enclosing_decl_locs[row["file"]].append((row["name"], row["start_line"], row["end_line"]))
        return enclosing_decl_locs

    def find_enclosing_declaration(self, start_line, end_line, decl_locs):
        closest_start_end = None
        for decl_loc in decl_locs:
            if decl_loc[1] <= start_line and end_line <= decl_loc[2]:
                if closest_start_end is None:
                    closest_start_end = decl_loc
                else:
                    if decl_loc[1] > closest_start_end[1]:
                        closest_start_end = decl_loc
        return closest_start_end

    def is_valid_alarm(self, alarm):
        if "codeFlows" not in alarm:
            return False
        else:
            return len(alarm["codeFlows"]) > 0

    def get_source_line(self, location):
        relative_file_url = location["location"]["physicalLocation"]["artifactLocation"]["uri"]
        line_num = location["location"]["physicalLocation"]["region"]["startLine"]
        file_dir = f"{self.project_source_code_dir}/{relative_file_url}"
        if not os.path.exists(file_dir):
            print("Not found ", file_dir)
            return ""
        else:
            file_lines = list(open(file_dir, 'r').readlines())
            if line_num > len(file_lines):
                return ""
            else:
                line = file_lines[line_num - 1]
                return line

    def is_valid_code_flow(self, code_flow, source_is_func_param, project_methods):
        thread_flow = code_flow["threadFlows"][0]
        locations = thread_flow["locations"]
    
        # if source_is_func_param:
        #     source_loc = locations[0]
        #     source_file_url = source_loc["location"]["physicalLocation"]["artifactLocation"]["uri"]
        #     source_start_line = source_loc["location"]["physicalLocation"]["region"]["startLine"]
        #     source_enclosing_func = self.find_enclosing_declaration(source_start_line, source_start_line, project_methods[source_file_url])

        snk_line = self.get_source_line(locations[-1])
        if ".println(" in snk_line or ".print(" in snk_line:
            return False

        for loc in locations:
            file_url = loc["location"]["physicalLocation"]["artifactLocation"]["uri"]
            if "src/test" in file_url:
                return False

        return True

    def post_process_cwe_query_result(self):
        self.project_logger.info("==> Stage 10: Post-processing CWE query results...")
        original_result_sarif = json.load(open(self.query_output_result_sarif_path))
        alarms = original_result_sarif["runs"][0]["results"]

        # 1. Extract class and function locations
        self.project_logger.info("  ==> Extracting function and class locations...")
        self.extract_func_locations()
        project_methods = self.extract_enclosing_decl_locs_map(pd.read_csv(self.func_locs_path))

        # 2. Print statistics
        num_alarms = len(alarms)
        num_paths = sum([len(alarm["codeFlows"]) for alarm in alarms if "codeFlows" in alarm])
        self.project_logger.info(f"  ==> Original #alarms: {num_alarms}; Original #paths: {num_paths}")

        # Do a few things
        # 1. remove the paths with node location containing `src/test`
        # 2. if the path starts with a function parameter of `f`, and that the path
        #    contains anything after a `return` statement inside that function `f`
        for alarm in alarms:
            source_is_func_param = "user-provided value as public function parameter" in alarm["message"]["text"]
            if "codeFlows" in alarm:
                alarm["codeFlows"] = [cf for cf in alarm["codeFlows"] if self.is_valid_code_flow(cf, source_is_func_param, project_methods)]

        # 3. Remove the alarms with no code-flows
        alarms = [alarm for alarm in alarms if self.is_valid_alarm(alarm)]
        new_num_alarms = len(alarms)
        new_num_paths = sum([len(alarm["codeFlows"]) for alarm in alarms if "codeFlows" in alarm])
        self.project_logger.info(f"  ==> New #alarms: {new_num_alarms}; New #paths: {new_num_paths}")

        # 4. Save the result back to the sarif
        original_result_sarif["runs"][0]["results"] = alarms
        if not self.test_run:
            json.dump(original_result_sarif, open(self.query_output_result_sarif_pp_path, "w"))

    def query_gpt_for_posthoc_filtering(self):
        self.project_logger.info("==> Stage 11: Querying GPT for posthoc filtering...")
        if self.skip_posthoc_filter:
            self.project_logger.info("  ==> Skipping posthoc filter...")
            return

        # 1. Extract class and function locations
        self.project_logger.info("  ==> Extracting function and class locations...")
        self.extract_class_locations()
        self.extract_func_locations()

        # 2. Create and run the pipeline
        contextual_analysis_pipeline = ContextualAnalysisPipeline(
            self.query,
            self.cwe_id,
            self.llm,
            self.seed,
            self.class_locs_path,
            self.func_locs_path,
            self.project_fixed_methods,
            self.query_output_result_sarif_pp_path,
            self.posthoc_filtering_output_log_path,
            self.posthoc_filtering_output_result_json_path,
            self.posthoc_filtering_output_result_sarif_path,
            self.posthoc_filtering_output_stats_json_path,
            self.project_source_code_dir,
            self.project_logger,
            self.overwrite,
            self.overwrite_posthoc_filter,
            self.test_run,
            posthoc_filtering_skip_fp=self.posthoc_filtering_skip_fp,
            rerun_skipped_fp=self.posthoc_filtering_rerun_skipped_fp,
        )
        contextual_analysis_pipeline.run()

    def build_evaluation_pipeline(self):
        return EvaluationPipeline(
            self.project_fixed_methods,
            self.class_locs_path,
            self.func_locs_path,
            self.project_source_code_dir,
            self.external_apis_csv_path,
            self.candidate_apis_csv_path,
            self.llm_labelled_sink_apis_path,
            self.llm_labelled_source_apis_path,
            self.llm_labelled_taint_prop_apis_path,
            self.source_func_param_candidates_path,
            self.llm_labelled_source_func_params_path,
            self.query_output_result_sarif_pp_path,
            self.posthoc_filtering_output_result_sarif_path,
            self.final_output_json_path,
            self.project_logger,
            overwrite=self.overwrite or self.overwrite_posthoc_filter or self.overwrite_cwe_query_result,
            test_run=self.test_run,
        )

    def evaluate_result(self):
        self.project_logger.info("==> Stage 12: Evaluating results...")
        if self.skip_evaluation:
            self.project_logger.info("  ==> skipping evaluation...")
            return

        # 1. Extract class and function locations
        self.project_logger.info("  ==> Extracting function and class locations...")
        self.extract_class_locations()
        self.extract_func_locations()

        # 2. Build
        eval_pipeline = self.build_evaluation_pipeline()
        eval_pipeline.run()

    def debug_result(self):
        if self.test_run:
            return

        # Debug source information
        if self.debug_source:
            if self.overwrite or self.overwrite_debug_info or not os.path.exists(f"{self.project_output_path}/fetch_sources/cwe-{self.cwe_id}/results.csv"):
                self.project_logger.info("==> Stage 10.1: Debug sources...")
                self.run_simple_codeql_query("fetch_sources", suffix=f"cwe-{self.cwe_id}", dyn_queries={"MySources.qll": self.build_source_qll_with_enumeration()})

        # Debug sink information
        if self.debug_sink:
            if self.overwrite or self.overwrite_debug_info or not os.path.exists(f"{self.project_output_path}/fetch_sinks/cwe-{self.cwe_id}/results.csv"):
                self.project_logger.info("==> Stage 10.1: Debug sinks...")
                self.run_simple_codeql_query("fetch_sinks", suffix=f"cwe-{self.cwe_id}", dyn_queries={"MySinks.qll": self.build_sink_qll_with_enumeration()})

    def run(self):
        # Check if we need to continue running
        if os.path.exists(self.query_output_result_sarif_pp_path) and os.path.exists(self.posthoc_filtering_output_result_sarif_path) \
           and not self.overwrite and not self.overwrite_cwe_query_result \
           and not self.overwrite_postprocess_cwe_query_result \
           and not self.overwrite_posthoc_filter \
           and not self.posthoc_filtering_rerun_skipped_fp \
           or self.evaluation_only:
            self.master_logger.info(f"==> Cached final result found; skipping")
            self.post_process_cwe_query_result()
            self.evaluate_result()
            self.debug_result()
            exit(1)

        # 1. Collect all the invoked external APIs
        self.collect_invoked_external_apis()
        # self.cwe_output_path/candidate_apis.csv

        #2.analyze all the invoked external APIS
        self.analyze_apis()

        # 3. Collect all the internal function parameters
        self.collect_internal_function_parameters()
        # self.common_output_path/source_func_param_candidates.csv

        # 4.Analyze all the internal function parameters
        self.analyze_internal_function_parameters()

        # 5. Query GPT for source/taint-propagator/sink from external APIs
        self.query_gpt_for_api_src_tp_sink_batched()
        #self.llm_labelled_sink_apis_path = f"{self.cwe_output_path}/llm_labelled_sink_apis.json"
        #self.llm_labelled_source_apis_path = f"{self.cwe_output_path}/llm_labelled_source_apis.json"
        #self.llm_labelled_taint_prop_apis_path = f"{self.cwe_output_path}/llm_labelled_taint_prop_apis.json"

        # 6. Query GPT for sources among internal function parameters
        self.query_gpt_for_func_param_src()
        # self.llm_labelled_source_func_params_path = f"{self.common_output_path}/llm_labelled_source_func_params.json"

        # 7. Label transmission with RAG 
        self.label_transmit_with_rag()

        # 8. Build local query for this project
        self.build_project_specific_query()
        # # CodeQL queries temporary path
        # self.source_qll_path = f"{self.cwe_output_path}/MySources.qll"
        # self.summary_qll_path = f"{self.cwe_output_path}/MySummaries.qll"
        # self.sink_qll_path = f"{self.cwe_output_path}/MySinks.qll"
        # self.spec_yml_path = f"{self.cwe_output_path}/Spec.yml"

        # 9. Send the local query for vulnerability detection
        self.find_vulnerability()
        # self.query_output_result_sarif_path = f"{self.query_output_path}/results.sarif"
        # self.query_output_result_csv_path = f"{self.query_output_path}/results.csv"

        # 10. Do a post-processing step for rule-based filtering of paths
        self.post_process_cwe_query_result()
        # 对CodeQL检测出的漏洞结果进行“后处理”，
        # 过滤掉无效、无意义或误报的路径和告警，
        # 以提升最终输出结果的准确性和可用性

        # 11. Do posthoc filtering
        self.query_gpt_for_posthoc_filtering()
        # self.posthoc_filtering_output_result_sarif_path = f"{self.posthoc_filtering_output_path}/results.sarif"
        # self.posthoc_filtering_output_result_json_path = f"{self.posthoc_filtering_output_path}/results.json"
        # self.posthoc_filtering_output_stats_json_path = f"{self.posthoc_filtering_output_path}/stats.json"

        # 12. Evaluate performance
        self.evaluate_result()
        # self.final_output_json_path = f"{self.final_output_path}/results.json"

        # 13. Debuggging
        self.debug_result()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("project", type=str)
    parser.add_argument("--query", type=str, default="022", required=True)
    parser.add_argument("--llm", type=str, default="gpt-4")
    parser.add_argument("--run-id", type=str, default="default")
    parser.add_argument("--seed", type=int, default=1234)
    parser.add_argument("--label-api-batch-size", type=int, default=30)
    parser.add_argument("--label-func-param-batch-size", type=int, default=20)
    parser.add_argument("--num-threads", type=int, default=3)
    parser.add_argument("--no-summary-model", action="store_true")
    parser.add_argument("--use-exhaustive-qll", action="store_true")
    parser.add_argument("--filter-by-module", action="store_true")
    parser.add_argument("--filter-by-module-large", action="store_true")
    parser.add_argument("--skip-huge-project", action="store_true")
    parser.add_argument("--skip-huge-project-num-apis-threshold", type=int, default=3000)
    parser.add_argument("--skip-posthoc-filter", action="store_true")
    parser.add_argument("--skip-evaluation", action="store_true")
    parser.add_argument("--posthoc-filtering-skip-fp", action="store_true")
    parser.add_argument("--posthoc-filtering-rerun-skipped-fp", action="store_true")
    parser.add_argument("--evaluation-only", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--overwrite-api-candidates", action="store_true")
    parser.add_argument("--overwrite-func-param-candidates", action="store_true")
    parser.add_argument("--overwrite-labelled-apis", action="store_true")
    parser.add_argument("--overwrite-llm-cache", action="store_true")
    parser.add_argument("--overwrite-labelled-func-param", action="store_true")
    parser.add_argument("--overwrite-cwe-query-result", action="store_true")
    parser.add_argument("--overwrite-postprocess-cwe-query-result", action="store_true")
    parser.add_argument("--overwrite-posthoc-filter", action="store_true")
    parser.add_argument("--overwrite-debug-info", action="store_true")
    parser.add_argument("--debug-source", action="store_true")
    parser.add_argument("--debug-sink", action="store_true")
    parser.add_argument("--test-run", action="store_true")
    parser.add_argument("--overwrite-analyze-api", action="store_true")
    parser.add_argument("--overwrite-analyze-func", action="store_true")
    parser.add_argument("--analysis", action="store_true")
    parser.add_argument("--skip-api-transmit", action="store_true")
    parser.add_argument("--skip-func-transmit", action="store_true")
    args = parser.parse_args()

    # Set basic properties
    args.use_exhaustive_qll = True

    pipeline = SAPipeline(
        args.project,
        args.query,
        run_id=args.run_id,
        llm=args.llm,
        label_api_batch_size=args.label_api_batch_size,
        label_func_param_batch_size=args.label_func_param_batch_size,
        num_threads=args.num_threads,
        seed=args.seed,
        no_summary_model=args.no_summary_model,
        use_exhaustive_qll=args.use_exhaustive_qll,
        skip_huge_project=args.skip_huge_project,
        skip_huge_project_num_apis_threshold=args.skip_huge_project_num_apis_threshold,
        skip_posthoc_filter=args.skip_posthoc_filter,
        skip_evaluation=args.skip_evaluation,
        filter_by_module=args.filter_by_module,
        filter_by_module_large=args.filter_by_module_large,
        posthoc_filtering_skip_fp=args.posthoc_filtering_skip_fp,
        posthoc_filtering_rerun_skipped_fp=args.posthoc_filtering_rerun_skipped_fp,
        evaluation_only=args.evaluation_only,
        overwrite=args.overwrite,
        overwrite_api_candidates=args.overwrite_api_candidates,
        overwrite_func_param_candidates=args.overwrite_func_param_candidates,
        overwrite_labelled_apis=args.overwrite_labelled_apis,
        overwrite_llm_cache=args.overwrite_llm_cache,
        overwrite_labelled_func_param=args.overwrite_labelled_func_param,
        overwrite_cwe_query_result=args.overwrite_cwe_query_result,
        overwrite_postprocess_cwe_query_result=args.overwrite_postprocess_cwe_query_result,
        overwrite_posthoc_filter=args.overwrite_posthoc_filter,
        overwrite_debug_info=args.overwrite_debug_info,
        debug_source=args.debug_source,
        debug_sink=args.debug_sink,
        test_run=args.test_run,
        overwrite_analyze_api=args.overwrite_analyze_api,
        overwrite_analyze_func=args.overwrite_analyze_func,
        analysis=args.analysis,
        skip_api_transmit=args.skip_api_transmit,
        skip_func_transmit=args.skip_func_transmit,
    )

    pipeline.run()
