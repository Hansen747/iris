import os, json
import pandas as pd
from src.config import CVES_MAPPED_W_COMMITS_DIR
from src.queries import QUERIES

query = 'cwe-022wLLM'
out = {}

out['query'] = query
out['csv_path'] = CVES_MAPPED_W_COMMITS_DIR

if not os.path.isfile(CVES_MAPPED_W_COMMITS_DIR):
    out['error'] = f'CSV missing: {CVES_MAPPED_W_COMMITS_DIR}'
else:
    df = pd.read_csv(CVES_MAPPED_W_COMMITS_DIR)
    out['csv_rows'] = len(df)
    out['csv_columns'] = df.columns.tolist()
    cols_needed = ['project_slug','cve_id','github_tag']
    out['missing_columns'] = [c for c in cols_needed if c not in df.columns]
    try:
        out['sample_head'] = df[cols_needed].head(20).to_dict('records')
    except Exception as e:
        out['sample_head_error'] = str(e)
    cwe_id = QUERIES[query]['cwe_id']
    out['cwe_id'] = cwe_id
    proj_tags = df.dropna(subset=cols_needed)
    candidates = []
    for _, row in df.iterrows():
        if f"CWE-{cwe_id}" not in str(row.get('cve_id','')).split(';'):
            continue
        hits = proj_tags[proj_tags['cve_id'] == row['cve_id']]
        if len(hits) == 0:
            continue
        proj_slug = hits.iloc[0]['project_slug']
        candidates.append(proj_slug)
    unique = list(set(candidates))
    out['unique_count'] = len(unique)
    out['unique_sample'] = unique[:200]
    present = [p for p in unique if os.path.isdir(f'/data/codeql_db/{p}')]
    missing = [p for p in unique if p not in present]
    out['present_count'] = len(present)
    out['present_sample'] = present[:200]
    out['missing_count'] = len(missing)
    out['missing_sample'] = missing[:200]

with open('/tmp/diag_cves.json','w') as f:
    json.dump(out, f, indent=2)
print('Wrote /tmp/diag_cves.json')
