API_LABELLING_SYSTEM_PROMPT = """\
You are a security expert. \
You are given a list of APIs to be labeled as potential taint sources, sinks, or APIs that propagate taints. \
Taint sources are values that an attacker can use for unauthorized and malicious operations when interacting with the system. \
Taint source APIs usually return strings or custom object types. Setter methods are typically NOT taint sources. \
Taint sinks are program points that can use tainted data in an unsafe way, which directly exposes vulnerability under attack. \
Taint propagators carry tainted information from input to the output without sanitization, and typically have non-primitive input and outputs. \
Return the result as a json list with each object in the format:

{ "package": <package name>,
  "class": <class name>,
  "method": <method name>,
  "signature": <signature of the method>,
  "sink_args": <list of arguments or `this`; empty if the API is not sink>,
  "type": <"source", "sink", or "taint-propagator"> }

DO NOT OUTPUT ANYTHING OTHER THAN JSON.\
"""


API_LABELLING_USER_PROMPT = """\
{cwe_long_description}

Some example source/sink/taint-propagator methods are:
{cwe_examples}

Among the following methods, \
assuming that the arguments passed to the given function is malicious, \
what are the functions that are potential source, sink, or taint-propagators to {cwe_description} attack (CWE-{cwe_id})?

Package,Class,Method,Signature,Analysis
{methods}
"""

# 系统提示（强调全面分析，避免明确分类）
API_ANALYSIS_SYSTEM_PROMPT = """\
You are an expert security analyst specializing in taint analysis and API security. Your task is to analyze APIs to identify features relevant to taint analysis in the context of {cwe_description} (CWE-{cwe_id}).

For API analysis, use a two-tier approach:
1. For well-known libraries/frameworks (e.g., Vert.x, Spring, Java Standard Library) with publicly documented APIs: Use your existing knowledge of the library's design, common usage patterns, and official documentation to enhance analysis depth.
2. For unknown or custom APIs: Base analysis SOLELY on observable clues (package, class name, method name, signature) without assuming implementation details.

CWE Context: 
{cwe_long_description} 

Examples include: 
{cwe_examples}

Taint analysis fundamentals:
- Potential sources: May introduce external/untrusted data (e.g., user input, network data)
- Potential sinks: May perform sensitive operations (e.g., database queries, command execution)
- Potential propagators: May transfer data without neutralizing taint

Output format rules:
- Single paragraph per API, starting with**[full_signature]**: 
- Clearly distinguish between:
  - Known facts (for well-known APIs: "As documented in Vert.x, this method...")
  - Inferences (for any API: "Likely performs... based on naming/signature")
  - Taint relevance: Specific features suggesting potential role as source/sink/propagator

Analysis dimensions (must cover all):
1. Functional behavior: What the API does (using known documentation where available)
2. Data handling: How it processes input parameters and propagates data
3. Security context: Relevance to {cwe_description} (CWE-{cwe_id})
4. Taint potential: Specific attributes supporting potential classification (without definitive labeling)

Use confident language for documented behaviors of well-known APIs, and tentative language for inferences from signature alone.
"""

# 用户提示（优化示例，更注重多维度分析）
API_ANALYSIS_USER_PROMPT = """

Examples of HIGH-QUALITY analysis (follow this structure):
1. **io.vertx.ext.web.RoutingContext.getBodyAsString()**: String: Per Vert.x docs, this method returns raw HTTP request body as String. It ingests untrusted client-supplied data with no implicit validation, directly crossing the trust boundary. Relevant to {cwe_description} (CWE-{cwe_id}) as a primary entry point for malicious input. Its role in exposing raw user data makes it a strong taint source candidate.
   
2. **java.lang.StringBuilder.append(String str)**: StringBuilder: Java's StringBuilder concatenates input String to its buffer, returning the modified instance. Transfers data without validation, aggregating potentially tainted content. While not directly exploiting {cwe_description}, it propagates taint through string aggregation, fitting taint-propagator .characteristics.
   
3. **com.example.data.Processor.transform(DataObject)**: DataObject: From signature clues, likely transforms DataObject instances (input → output). May handle internal data transfer, but transformation details are unknown. If DataObject contains user data, could propagate taint relevant to CWE-{cwe_id}, suggesting potential as a propagator.

Analyze the following APIs. Output a numbered list matching the input order:
{api_list}
"""


FUNC_PARAM_LABELLING_SYSTEM_PROMPT = """\
You are a security expert. \
You are given a list of APIs implemented in established Java libraries, \
and you need to identify whether some of these APIs could be potentially invoked by downstream libraries with malicious end-user (not programmer) inputs. \
For instance, functions that deserialize or parse inputs might be used by downstream libraries and would need to add sanitization for malicious user inputs. \
On the other hand, functions like HTTP request handlers are typically final and won't be called by a downstream package. \
Utility functions that are not related to the primary purpose of the package should also be ignored. \
Return the result as a json list with each object in the format:

{ "package": <package name>,
  "class": <class name>,
  "method": <method name>,
  "signature": <signature>,
  "tainted_input": <a list of argument names that are potentially tainted> }

In the result list, only keep the functions that might be used by downstream libraries and is potentially invoked with malicious end-user inputs. \
Do not output anything other than JSON.\
"""

FUNC_PARAM_LABELLING_USER_PROMPT = """\
You are analyzing the Java package {project_username}/{project_name}. \
Here is the package summary:

{project_readme_summary}

Please look at the following public methods in the library and their documentations (if present). \
What are the most important functions that look like can be invoked by a downstream Java package that is dependent on {project_name}, \
and that the function can be called with potentially malicious end-user inputs? \
If the package does not seem to be a library, just return empty list as the result. \
Utility functions that are not related to the primary purpose of the package should also be ignored

Package,Class,Method,Doc,Analysis
{methods}
"""

# 系统提示和用户提示模板
METHOD_ANALYSIS_SYSTEM_PROMPT = """\
You are an expert in code security and taint analysis.
Your task is to analyze methods to determine if they might be potential taint sources in a security context.
A taint source is a method that may receive untrusted input from end-users, which could contain malicious content.
Consider if the method handles user input, is used by downstream libraries, or processes external data.
Provide your analysis in clear, natural language.
"""

METHOD_ANALYSIS_USER_PROMPT = """Please analyze the following methods to determine if they could be potential taint sources in a security context.

For each method, provide a brief, coherent analysis in natural language (2-3 sentences) covering:
1. What this method does (using documentation if available)
2. Whether it might receive malicious input from end-users
3. Its potential as a taint source (high/medium/low/none)
4. Key reasoning for your assessment

{method_list}

Format your response as a JSON object with a top-level key 'analyses', containing an array of objects with:
- 'method_index' (0-based index matching the input list)
- 'natural_language_analysis' (a single string with the natural language analysis)

Example:
{{
    "analyses": [
        {{
            "method_index": 0,
            "natural_language_analysis": "spark.Request.params retrieves route pattern parameter values. It likely receives malicious input from end-users and has high potential as a taint source since it directly handles untrusted user-provided parameters."
        }},
        {{
            "method_index": 1,
            "natural_language_analysis": "spark.Request.attribute gets attribute values from a request. It has medium potential as a taint source since attributes might contain user-derived data, though they're typically set by the application rather than directly from users."
        }}
    ]
}}
"""

POSTHOC_FILTER_SYSTEM_PROMPT = """\
You are an expert in detecting security vulnerabilities. \
You are given the starting point (source) and the ending point (sink) of a dataflow path in a Java project that may be a potential vulnerability. \
Analyze the given taint source and sink and predict whether the given dataflow can be part of a vulnerability or not, and store it as a boolean in "is_vulnerable". \
Note that, the source must be either a) the formal parameter of a public library function which might be invoked by a downstream package, or b) the result of a function call that returns tainted input from end-user. \
If the given source or sink do not satisfy the above criteria, mark the result as NOT VULNERABLE. \
Please provide a very short explanation associated with the verdict. \
Assume that the intermediate path has no sanitizer.

Answer in JSON object with the following format:

{ "explanation": <YOUR EXPLANATION>,
  "source_is_false_positive": <true or false>,
  "sink_is_false_positive": <true or false>,
  "is_vulnerable": <true or false> }

Do not include anything else in the response.\
"""

POSTHOC_FILTER_USER_PROMPT = """\
Analyze the following dataflow path in a Java project and predict whether it contains a {cwe_description} vulnerability ({cwe_id}), or a relevant vulnerability.
{hint}

Source ({source_msg}):
```
{source}
```

Steps:
{intermediate_steps}

Sink ({sink_msg}):
```
{sink}
```\
"""

POSTHOC_FILTER_USER_PROMPT_W_CONTEXT = """\
Analyze the following dataflow path in a Java project and predict whether it contains a {cwe_description} vulnerability ({cwe_id}), or a relevant vulnerability.
{hint}

Source ({source_msg}):
```
{source}
```

Steps:
{intermediate_steps}

Sink ({sink_msg}):
```
{sink}
```

{context}\
"""
# The key should be the CWE number without any string prefixes. 
# The value should be sentences describing more specific details for detecting the CWE. 
POSTHOC_FILTER_HINTS = {
    "022": "Note: please be careful about defensing against absolute paths and \"..\" paths. Just canonicalizing paths might not be sufficient for the defense.",
    "078": "Note that other than typical Runtime.exec which is directly executing command, using Java Reflection to create dynamic objects with unsanitized inputs might also cause OS Command injection vulnerability. This includes deserializing objects from untrusted strings and similar functionalities. Writing to config files about library data may also induce unwanted execution of OS commands.",
    "079": "Please be careful about reading possibly tainted HTML input. During sanitization, do not assume the sanitization to be sufficient.",
    "094": "Please note that dubious error messages can sometimes be handled by downstream code for execution, resulting in CWE-094 vulnerability. Injection of malicious values might lead to arbitrary code execution as well.",
}

SNIPPET_CONTEXT_SIZE = 4
