import csv
import json
import os
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

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
            similarity_threshold: float = 0.7
    ):
        # 原有初始化参数
        self.project_name = project_name
        self.query = query
        self.run_id = run_id
        self.llm = llm
        self.label_api_batch_size = label_api_batch_size
        self.label_func_param_batch_size = label_func_param_batch_size
        self.num_threads = num_threads
        self.seed = seed
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
        self.model = SentenceTransformer(model_name)
        
        # 可以在这里定义文件路径，或者从配置中获取
        self.analysed_apis_path = "analysed_apis.csv"
        self.analysed_func_params_path = "analysed_func_params.csv"
        self.source_apis_path = "llm_labelled_source_apis.json"
        self.sink_apis_path = "llm_labelled_sink_apis.json"
        self.taint_prop_apis_path = "llm_labelled_taint_prop_apis.json"
        self.source_func_params_path = "llm_labelled_source_func_params.json"

    # ------------------------------
    # API标签传播相关方法
    # ------------------------------
    def load_analysed_apis(self):
        """加载分析过的API数据并构建向量知识库"""
        print(f"加载并处理API数据: {self.analysed_apis_path}")
        
        if not os.path.exists(self.analysed_apis_path):
            print(f"API数据文件不存在: {self.analysed_apis_path}")
            return
            
        with open(self.analysed_apis_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # 对analysis文本进行向量化
                analysis_text = row['analysis']
                embedding = self.model.encode(analysis_text)
                
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
        if os.path.exists(self.source_apis_path):
            with open(self.source_apis_path, 'r', encoding='utf-8') as f:
                self.labelled_apis['source'] = json.load(f)
            print(f"加载源函数 {len(self.labelled_apis['source'])} 个")
        
        # 加载sink函数
        if os.path.exists(self.sink_apis_path):
            with open(self.sink_apis_path, 'r', encoding='utf-8') as f:
                self.labelled_apis['sink'] = json.load(f)
            print(f"加载sink函数 {len(self.labelled_apis['sink'])} 个")
        
        # 加载污点传播函数
        if os.path.exists(self.taint_prop_apis_path):
            with open(self.taint_prop_apis_path, 'r', encoding='utf-8') as f:
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

    def propagate_api_labels(self, top_k=5):
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
            similar_functions = self._find_similar_labelled_functions(
                func, self.labelled_apis, self.vector_db_apis, top_k)
            
            if not similar_functions:
                continue
                
            # 检查最高相似度是否超过阈值
            top_similar = similar_functions[0]
            if top_similar['similarity'] >= self.similarity_threshold:
                # 创建新的标签条目
                new_entry = {
                    'package': func['package'],
                    'class': func['class'],
                    'method': func['method'],
                    'signature': func['signature'],
                    # 根据标签类型设置相应的参数
                    'sink_args': top_similar['function'].get('sink_args', []) if top_similar['label_type'] == 'sink' else [],
                    'source_args': top_similar['function'].get('source_args', []) if top_similar['label_type'] == 'source' else [],
                    'propagate_args': top_similar['function'].get('propagate_args', []) if top_similar['label_type'] == 'taint-propagator' else [],
                    'type': top_similar['label_type'],
                    'similarity': round(top_similar['similarity'], 4)
                }
                
                # 添加到相应的标签组
                propagated[top_similar['label_type']].append(new_entry)
        
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
                embedding = self.model.encode(analysis_text)
                
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
        if os.path.exists(self.source_func_params_path):
            with open(self.source_func_params_path, 'r', encoding='utf-8') as f:
                self.labelled_func_params = json.load(f)
            print(f"加载已标记的函数参数 {len(self.labelled_func_params)} 个")
        else:
            print(f"未找到已标记的函数参数文件: {self.source_func_params_path}")
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

    def propagate_func_param_labels(self, top_k=5):
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
            similar_functions = self._find_similar_labelled_params(
                func, self.labelled_func_params, self.vector_db_func_params, top_k)
            
            if not similar_functions:
                continue
                
            # 检查最高相似度是否超过阈值
            top_similar = similar_functions[0]
            if top_similar['similarity'] >= self.similarity_threshold:
                # 创建新的标签条目，tainted_input为新标记函数的所有形参
                new_entry = {
                    'package': func['package'],
                    'class': func['class'],
                    'method': func['method'],
                    'signature': func['signature'],
                    'tainted_input': func['parameters'],  # 使用解析出的所有参数
                    'similarity': round(top_similar['similarity'], 4)
                }
                
                propagated.append(new_entry)
        
        print(f"函数参数标签传播完成，共为 {len(propagated)} 个函数自动标记标签")
        
        # 保存结果
        self._save_propagated_func_params(propagated)

    # ------------------------------
    # 内部辅助方法
    # ------------------------------
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

    def _find_most_similar_labelled_function(self, target_func, labelled_functions, vector_db):
        """找到最相似的已标记函数（只返回最相似的一个）"""
        labelled_with_labels = []
        for label_type, functions in labelled_functions.items():
            for func in functions:
                # 在向量库中找到对应的函数以获取embedding
                match = next((f for f in vector_db 
                             if f['package'] == func['package'] 
                             and f['class'] == func['class']
                             and f['method'] == func['method']
                             and f['signature'] == func['signature']), None)
                
                if match:
                    labelled_with_labels.append({
                        'function': func,
                        'label_type': label_type,
                        'embedding': match['embedding']
                    })
        
        if not labelled_with_labels:
            return None
        
        # 计算目标函数与所有已标记函数的相似度
        target_embedding = target_func['embedding'].reshape(1, -1)
        max_similarity = -1
        most_similar = None
        
        for item in labelled_with_labels:
            emb = item['embedding'].reshape(1, -1)
            similarity = cosine_similarity(target_embedding, emb)[0][0]
            
            # 只保留相似度最高的那个
            if similarity > max_similarity:
                max_similarity = similarity
                most_similar = {
                    'function': item['function'],
                    'label_type': item['label_type'],
                    'similarity': similarity
                }
        
        return most_similar

    def _find_most_similar_labelled_param(self, target_func, labelled_params, vector_db):
        """找到最相似的已标记函数参数（只返回最相似的一个）"""
        labelled_with_embeddings = []
        for func in labelled_params:
            # 在向量库中找到对应的函数以获取embedding
            match = next((f for f in vector_db 
                         if f['package'] == func['package'] 
                         and f['class'] == func['class']
                         and f['method'] == func['method']
                         and f['signature'] == func['signature']), None)
            
            if match:
                labelled_with_embeddings.append({
                    'function': func,
                    'embedding': match['embedding']
                })
        
        if not labelled_with_embeddings:
            return None
        
        # 计算目标函数与所有已标记函数的相似度
        target_embedding = target_func['embedding'].reshape(1, -1)
        max_similarity = -1
        most_similar = None
        
        for item in labelled_with_embeddings:
            emb = item['embedding'].reshape(1, -1)
            similarity = cosine_similarity(target_embedding, emb)[0][0]
            
            # 只保留相似度最高的那个
            if similarity > max_similarity:
                max_similarity = similarity
                most_similar = {
                    'function': item['function'],
                    'similarity': similarity
                }
        
        return most_similar
    def _save_propagated_apis(self, propagated_labels):
        """保存传播后的API标签到对应的JSON文件"""
        # 保存source函数
        if propagated_labels['source']:
            self._save_propagated_labels(
                propagated_labels['source'], 
                self.source_apis_path,
                'source'
            )
        
        # 保存sink函数
        if propagated_labels['sink']:
            self._save_propagated_labels(
                propagated_labels['sink'], 
                self.sink_apis_path,
                'sink'
            )
        
        # 保存taint-propagator函数
        if propagated_labels['taint-propagator']:
            self._save_propagated_labels(
                propagated_labels['taint-propagator'], 
                self.taint_prop_apis_path,
                'taint-propagator'
            )

    def _save_propagated_func_params(self, propagated_labels):
        """保存传播后的函数参数标签到对应的JSON文件"""
        self._save_propagated_labels(
            propagated_labels, 
            self.source_func_params_path,
            'source'
        )

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

    # 在现有流程中可以添加一个方法来触发两次标签传播
    def run_label_propagation(self):
        """运行所有标签传播流程"""
        print("=== 开始API标签传播流程 ===")
        self.propagate_api_labels()
        
        print("\n=== 开始函数参数标签传播流程 ===")
        self.propagate_func_param_labels()
