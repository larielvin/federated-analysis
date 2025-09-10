# === Data summary notebook cell ===
# Works with: pandas, numpy (no extra libs required).
# Set DATASET_PATH to your CSV (e.g., "kenya_agri.csv").

from pathlib import Path
from typing import Union
import pandas as pd
import numpy as np

# ----------------------- config -----------------------
DATASET_PATH = "kenya_agri_synthetic.csv"            # <-- change if needed
TARGET_COL   = "default_or_claim"
SPLIT_COL    = "split"

# Feature groups used in training (will auto-intersect with actual columns)
PARTY_FEATURES = {
    "agritech": {
        "numeric": [
            "farm_area_ha", "input_cost_kes", "agritech_score",
            "mpesa_txn_count_90d", "mpesa_inflow_kes_90d", "eo_ndvi_gs",
        ],
        "categorical": ["crop_primary", "crop_secondary"],
        "boolean": ["irrigated"],
    },
    "bank": {
        "numeric": ["loan_amount_kes", "tenor_months", "interest_rate_pct"],
        "categorical": [],
        "boolean": ["prior_default"],
    },
    "processor": {
        "numeric": ["yield_t_ha", "sales_kes"],
        "categorical": [],
        "boolean": ["processor_contract"],
    },
    "insurance": {
        "numeric": ["climate_risk_index"],
        "categorical": [],
        "boolean": ["insured"],
    },
    "government": {
        "numeric": ["rain_mm_gs", "soil_quality_index"],
        "categorical": ["county"],
        "boolean": ["gov_subsidy"],
    },
}

# Optional derived ratios (computed only if source cols exist)
DERIVED_SPECS = {
    "total_yield_t":        ("farm_area_ha", "yield_t_ha"),            # product
    "farmgate_price_kes_t": ("sales_kes", "total_yield_t"),            # sales / total_yield
    "loan_to_sales":        ("loan_amount_kes", "sales_kes"),          # loan / sales
    "inflow_per_txn":       ("mpesa_inflow_kes_90d", "mpesa_txn_count_90d"), # inflow / txn
}

def load_df(path: Union[str, Path]) -> pd.DataFrame:
    df = pd.read_csv(path)
    # normalize booleans represented as strings
    for c in df.columns:
        if df[c].dtype == object:
            vals = set(str(v).strip().lower() for v in df[c].dropna().unique())
            if vals.issubset({"true","false","0","1"}):
                df[c] = df[c].map(lambda x: str(x).strip().lower()).replace({"true":1,"false":0}).astype("Int64")
    return df

def infer_types(df: pd.DataFrame, target: str) -> tuple[list[str], list[str], list[str]]:
    numeric = df.select_dtypes(include=[np.number]).columns.tolist()
    if target in numeric:
        numeric.remove(target)
    # categorical: object or low-cardinality integer-like that isn't boolean
    cat = df.select_dtypes(include=["object"]).columns.tolist()
    # boolean-ish: exact bool dtype or Int64/float with only {0,1} (ignoring NaN)
    bool_cols = []
    for c in df.columns:
        s = df[c].dropna()
        if s.dtype == bool:
            bool_cols.append(c)
        elif pd.api.types.is_integer_dtype(s) or pd.api.types.is_bool_dtype(s):
            if len(set(s.unique()).difference({0,1})) == 0 and c != target:
                bool_cols.append(c)
    # remove any overlaps
    cat = [c for c in cat if c not in bool_cols and c != target]
    numeric = [c for c in numeric if c not in bool_cols and c != target]
    return numeric, cat, bool_cols

def event_rate(y: pd.Series) -> float:
    y = y.astype(float)
    return float((y == 1).mean())

def safe_ratio(a: pd.Series, b: pd.Series) -> pd.Series:
    with np.errstate(divide="ignore", invalid="ignore"):
        r = a / b
        r.replace([np.inf, -np.inf], np.nan, inplace=True)
        return r

def add_derived(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    if set(["farm_area_ha","yield_t_ha"]).issubset(df.columns):
        df["total_yield_t"] = df["farm_area_ha"] * df["yield_t_ha"]
    if {"sales_kes","total_yield_t"}.issubset(df.columns):
        df["farmgate_price_kes_t"] = safe_ratio(df["sales_kes"], df["total_yield_t"])
    if {"loan_amount_kes","sales_kes"}.issubset(df.columns):
        df["loan_to_sales"] = safe_ratio(df["loan_amount_kes"], df["sales_kes"])
    if {"mpesa_inflow_kes_90d","mpesa_txn_count_90d"}.issubset(df.columns):
        df["inflow_per_txn"] = safe_ratio(df["mpesa_inflow_kes_90d"], df["mpesa_txn_count_90d"])
    return df

def party_coverage(df: pd.DataFrame, party_map: dict) -> pd.DataFrame:
    rows = []
    cols = set(df.columns)
    for party, spec in party_map.items():
        num = [c for c in spec.get("numeric",[]) if c in cols]
        cat = [c for c in spec.get("categorical",[]) if c in cols]
        boo = [c for c in spec.get("boolean",[]) if c in cols]
        rows.append({
            "party": party,
            "n_numeric_present": len(num),
            "n_categorical_present": len(cat),
            "n_boolean_present": len(boo),
            "total_present": len(num)+len(cat)+len(boo),
        })
    return pd.DataFrame(rows).sort_values("party")

def numeric_summary(df: pd.DataFrame, numeric_cols: list[str]) -> pd.DataFrame:
    if not numeric_cols:
        return pd.DataFrame()
    desc = df[numeric_cols].describe(percentiles=[0.25,0.5,0.75]).T
    desc.rename(columns={"50%":"median"}, inplace=True)
    miss = df[numeric_cols].isna().mean().rename("missing_rate")
    return desc.join(miss)

def boolean_summary(df: pd.DataFrame, bool_cols: list[str]) -> pd.DataFrame:
    rows = []
    for c in bool_cols:
        s = df[c]
        rows.append({
            "column": c,
            "pct_true": float((s == 1).mean(skipna=True)),
            "missing_rate": float(s.isna().mean())
        })
    return pd.DataFrame(rows).set_index("column")

def categorical_summary(df: pd.DataFrame, cat_cols: list[str], top_k: int = 10) -> dict[str, pd.DataFrame]:
    out = {}
    for c in cat_cols:
        vc = df[c].value_counts(dropna=False)
        top = vc.head(top_k).to_frame("count")
        top["fraction"] = top["count"] / len(df)
        out[c] = top
    return out

def missingness_table(df: pd.DataFrame) -> pd.DataFrame:
    miss = df.isna().mean().to_frame("missing_rate")
    miss["n_missing"] = (df.isna().sum())
    miss["dtype"] = [str(df[c].dtype) for c in miss.index]
    return miss.sort_values("missing_rate", ascending=False)

def base_rate_by(df: pd.DataFrame, target: str, group_col: str, min_n: int = 20) -> pd.DataFrame:
    if group_col not in df.columns:
        return pd.DataFrame()
    grp = df.groupby(group_col)[target]
    out = grp.agg(n="count", event_rate=lambda s: float((s==1).mean())).sort_values("n", ascending=False)
    return out[out["n"] >= min_n]

def corr_with_target(df: pd.DataFrame, numeric_cols: list[str], target: str) -> pd.DataFrame:
    if target not in df.columns or not numeric_cols:
        return pd.DataFrame()
    y = df[target].astype(float)
    out = df[numeric_cols].corrwith(y).to_frame("pearson_corr_to_target").sort_values("pearson_corr_to_target", ascending=False)
    return out
def export_excel(tables: dict, path: Union[str, Path]):
    try:
        with pd.ExcelWriter(path) as xw:
            for name, tbl in tables.items():
                if isinstance(tbl, pd.DataFrame) and not tbl.empty:
                    tbl.to_excel(xw, sheet_name=name[:31])
    except Exception as e:
        print(f"[warn] Excel export failed ({e}); writing CSVs instead.")
        outdir = Path(path).with_suffix("")
        outdir.mkdir(exist_ok=True)
        for name, tbl in tables.items():
            if isinstance(tbl, pd.DataFrame) and not tbl.empty:
                (outdir / f"{name}.csv").write_text(tbl.to_csv(index=True))
                (outdir / f"{name}.csv").write_text(tbl.to_csv(index=True))

# ----------------------- run -----------------------
df_raw = load_df(DATASET_PATH).copy()
assert TARGET_COL in df_raw.columns, f"Target column '{TARGET_COL}' not found"

# add deriveds
df = add_derived(df_raw)

# basic counts
n_all = len(df)
n_train = int((df[SPLIT_COL].str.lower() == "train").sum()) if SPLIT_COL in df.columns else np.nan
n_test  = int((df[SPLIT_COL].str.lower() == "test").sum())  if SPLIT_COL in df.columns else np.nan

# type inference
num_cols, cat_cols, bool_cols = infer_types(df, TARGET_COL)

# summaries
overall = pd.DataFrame({
    "n_rows": [n_all],
    "n_train": [n_train],
    "n_test": [n_test],
    "n_features_total": [df.shape[1]],
    "n_numeric": [len(num_cols)],
    "n_categorical": [len(cat_cols)],
    "n_boolean": [len(bool_cols)],
    "event_rate_overall": [event_rate(df[TARGET_COL])],
})
by_split = None
if SPLIT_COL in df.columns:
    by_split = (df.groupby(df[SPLIT_COL].str.lower())[TARGET_COL]
                  .agg(n="count", event_rate=lambda s: float((s==1).mean())))
else:
    by_split = pd.DataFrame()

party_cov = party_coverage(df, PARTY_FEATURES)
num_sum   = numeric_summary(df, num_cols + [c for c in ["total_yield_t","farmgate_price_kes_t","loan_to_sales","inflow_per_txn"] if c in df.columns])
bool_sum  = boolean_summary(df, [c for c in bool_cols if c != TARGET_COL])
cat_summ  = categorical_summary(df, cat_cols)
missing   = missingness_table(df)
by_county = base_rate_by(df, TARGET_COL, "county", min_n=20)
corr_t    = corr_with_target(df, [c for c in num_cols if c != TARGET_COL], TARGET_COL)

# display key tables (Jupyter will render them nicely)
print("=== OVERALL ===")
print("\n=== CLASS BALANCE BY SPLIT ===")
print("\n=== PARTY COVERAGE ===")
print("\n=== NUMERIC SUMMARY (incl. derived, if present) ===")
print("\n=== BOOLEAN SUMMARY ===")
print("\n=== MISSINGNESS BY COLUMN ===")
print("\n=== EVENT RATE BY COUNTY (n>=20) ===")
print("\n=== CORRELATION (numeric vs target) ===")

print("\n=== TOP CATEGORY LEVELS (first few columns) ===")
for c, tbl in list(cat_summ.items())[:5]:
    print(f"\n[categorical] {c}")

# optional: export to Excel with multiple sheets (or CSVs fallback)
tables_to_export = {
    "overall": overall,
    "class_balance_by_split": by_split,
    "party_coverage": party_cov,
    "numeric_summary": num_sum,
    "boolean_summary": bool_sum,
    "missingness": missing,
    "event_rate_by_county": by_county,
    "corr_with_target": corr_t,
}
export_excel(tables_to_export, "dataset_summary.xlsx")

print("\nSaved summaries to 'dataset_summary.xlsx' (or CSVs in 'dataset_summary/' if Excel writer unavailable).")
