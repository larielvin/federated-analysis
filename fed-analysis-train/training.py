from pathlib import Path
import argparse
import json
import copy
import pickle
import shutil
import time
from typing import Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix
)
from sklearn.pipeline import Pipeline as PipelineOr
from concrete.ml.sklearn import DecisionTreeClassifier
from concrete.ml.common.check_inputs import check_array_and_assert
from concrete.ml.common.utils import (
    generate_proxy_function,
    manage_parameters_for_pbs_errors,
    check_there_is_no_p_error_options_in_configuration,
)
from concrete.ml.quantization.quantized_module import _get_inputset_generator
from concrete.ml.deployment.fhe_client_server import FHEModelDev
from concrete.fhe.compilation.compiler import Compiler, Configuration, DebugArtifacts, Circuit


def parse_args():
    ap = argparse.ArgumentParser(description="Train & compile a multi-party FHE Decision Tree on CSV.")
    ap.add_argument("--csv", default="kenya_agri.csv", help="Path to dataset CSV.")
    ap.add_argument("--target", default="default_or_claim", help="Target column name.")
    ap.add_argument("--outdir", default="output/model", help="Directory to store artifacts.")
    ap.add_argument("--test_size", type=float, default=0.2, help="Test split fraction if 'split' column absent.")
    ap.add_argument("--max_depth", type=int, default=3, help="Tree max depth (FHE-friendly).")
    ap.add_argument("--random_state", type=int, default=42, help="Random seed for fallback split.")
    return ap.parse_args()


# ============================================================
# Feature grouping by party
# ============================================================

KNOWN_FEATURES: Dict[str, Dict[str, List[str]]] = {
    # Agritech (extension / agronomy / digital footprints)
    "agritech": {
        "numeric": [
            "farm_area_ha", "input_cost_kes", "agritech_score",
            "mpesa_txn_count_90d", "mpesa_inflow_kes_90d", "eo_ndvi_gs"
        ],
        "categorical": ["crop_primary", "crop_secondary"],
        "boolean": ["irrigated"],
    },
    # Bank (credit & lending)
    "bank": {
        "numeric": ["loan_amount_kes", "tenor_months", "interest_rate_pct"],
        "categorical": [],
        "boolean": ["prior_default"],  # prior credit events seen by lender/credit bureau
    },
    # Processor (offtake contracts & realized outputs)
    "processor": {
        "numeric": ["yield_t_ha", "sales_kes"],
        "categorical": [],
        "boolean": ["processor_contract"],
    },
    # Insurance (risk & coverage)
    "insurance": {
        "numeric": ["climate_risk_index"],
        "categorical": [],
        "boolean": ["insured"],
    },
    # Government (geo/soil/climate/subsidies/administrative)
    "government": {
        "numeric": ["rain_mm_gs", "soil_quality_index"],
        "categorical": ["county"],
        "boolean": ["gov_subsidy"],
    },
}


def intersect_group_with_df(df: pd.DataFrame, group_def: Dict[str, List[str]]) -> Dict[str, List[str]]:
    return {
        "numeric": [c for c in group_def.get("numeric", []) if c in df.columns],
        "categorical": [c for c in group_def.get("categorical", []) if c in df.columns],
        "boolean": [c for c in group_def.get("boolean", []) if c in df.columns],
    }


def build_group_preprocessor(cols: Dict[str, List[str]]) -> ColumnTransformer:
    num_cols = cols["numeric"]
    cat_cols = cols["categorical"]
    bool_cols = cols["boolean"]

    transformers = []
    if num_cols:
        transformers.append((
            "num",
            PipelineOr(steps=[
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler(with_mean=True, with_std=True)),
            ]),
            num_cols
        ))
    if cat_cols:
        transformers.append((
            "cat",
            PipelineOr(steps=[
                ("imputer", SimpleImputer(strategy="most_frequent")),
                ("ohe", OneHotEncoder(handle_unknown="ignore", sparse=False)),
            ]),
            cat_cols
        ))
    if bool_cols:
        # booleans are cast to int on the dataframe; impute just-in-case
        transformers.append((
            "bool",
            PipelineOr(steps=[
                ("imputer", SimpleImputer(strategy="most_frequent")),
            ]),
            bool_cols
        ))

    pre = ColumnTransformer(
        transformers=transformers,
        remainder="drop",
        sparse_threshold=0.0,
        verbose_feature_names_out=False,
    )
    return pre

def safe_feature_names_out(preproc: ColumnTransformer, raw_cols: List[str]) -> List[str]:
    """Return post-processed feature names in order; fall back to numbered columns if needed."""
    try:
        names = preproc.get_feature_names_out()
        return [str(n) for n in names]
    except Exception:
        # Fallback: infer width by transforming a single-row placeholder
        df = pd.DataFrame([{c: np.nan for c in raw_cols}], columns=raw_cols)
        arr = preproc.transform(df)
        return [f"col_{i}" for i in range(arr.shape[1])]


# ============================================================
# Multi-input wrapper 
# ============================================================

class MultiInputModel:
    def quantize_input(self, *X: np.ndarray):
        self._ensure_fitted()
        if not hasattr(self, "input_quantizers"):
            raise RuntimeError("Input quantizers not set. Ensure the model was fit with fit_benchmark.")
        if sum(inp.shape[1] for inp in X) != len(self.input_quantizers):
            raise ValueError("Mismatch between input dims and number of quantizers.")
        base = 0
        out = []
        for inp in X:
            q = np.zeros_like(inp, dtype=np.int64)
            for j in range(inp.shape[1]):
                q[:, j] = self.input_quantizers[base + j].quant(inp[:, j])
            out.append(q)
            base += inp.shape[1]
        return tuple(out) if len(out) > 1 else out[0]

    def compile(
        self,
        *inputs,
        configuration: Optional[Configuration] = None,
        artifacts: Optional[DebugArtifacts] = None,
        show_mlir: bool = False,
        p_error: Optional[float] = None,
        global_p_error: Optional[float] = None,
        verbose: bool = False,
        inputs_encryption_status: Optional[List[str]] = None,
    ) -> Circuit:
        self._ensure_fitted()
        inputs_as_array = tuple(check_array_and_assert(inp) for inp in inputs)
        check_there_is_no_p_error_options_in_configuration(configuration)
        p_error, global_p_error = manage_parameters_for_pbs_errors(p_error, global_p_error)

        # Default config (encrypted execution)
        if configuration is None:
            configuration = Configuration()
            configuration.verbose = False
            configuration.fhe_simulation = False
            configuration.fhe_execution = True

        # Prepare quantized representative inputset
        q_inputs = self.quantize_input(*inputs_as_array)
        inputset = _get_inputset_generator(q_inputs)

        # Make inference accept concatenated inputs
        if not getattr(self, "_is_compiled", False):
            original = self._tree_inference
            self._tree_inference = lambda *parts: original(np.concatenate(parts, axis=1))

        # Prepare proxy with named encrypted inputs
        if inputs_encryption_status is None:
            inputs_encryption_status = ["encrypted"] * len(inputs_as_array)
        input_names = [f"input_{i}_encrypted" for i in range(len(inputs_encryption_status))]
        proxy, arg_names = generate_proxy_function(self._tree_inference, input_names)
        statuses = {name: status for name, status in zip(arg_names.values(), inputs_encryption_status)}

        compiler = Compiler(proxy, statuses)

        t0 = time.time()
        self.fhe_circuit_ = compiler.compile(
            inputset,
            configuration=configuration,
            artifacts=artifacts,
            show_mlir=show_mlir,
            p_error=p_error,
            global_p_error=global_p_error,
            verbose=verbose,
            single_precision=False,
            fhe_simulation=False,
            fhe_execution=True,
        )
        t1 = time.time()
        self.compile_time_s_ = float(t1 - t0)
        self._is_compiled = True
        self.configuration = configuration
        return self.fhe_circuit_

    def _ensure_fitted(self):
        if not hasattr(self, "_is_fitted") or not self._is_fitted:
            raise RuntimeError("Model is not fitted yet.")

    def evaluate_with_time(self, *X_parts: np.ndarray, y_test: np.ndarray) -> dict:
        """Evaluate plaintext and FHE with timing."""
        self._ensure_fitted()

        # Plaintext
        X_concat = np.concatenate(X_parts, axis=1)
        t0 = time.time()
        y_pred_plain = self.predict(X_concat)
        t1 = time.time()
        plain_elapsed = float(t1 - t0)
        n = len(X_concat)
        plain_latency = plain_elapsed / max(1, n)

        plain = {
            "accuracy": accuracy_score(y_test, y_pred_plain),
            "precision": precision_score(y_test, y_pred_plain, average="binary", zero_division=0),
            "recall": recall_score(y_test, y_pred_plain, average="binary", zero_division=0),
            "f1_score": f1_score(y_test, y_pred_plain, average="binary", zero_division=0),
            "confusion_matrix": confusion_matrix(y_test, y_pred_plain).tolist(),
            "total_time_s": plain_elapsed,
            "num_samples": n,
            "latency_per_sample_s": plain_latency,
        }

        # FHE
        if not hasattr(self, "fhe_circuit_") or not self._is_compiled:
            raise RuntimeError("Compile before FHE evaluation.")

        q_parts = self.quantize_input(*X_parts)
        if not isinstance(q_parts, tuple):
            q_parts = (q_parts,)

        fhe_preds = []
        fhe_total = 0.0
        for i in range(q_parts[0].shape[0]):
            sample = tuple(part[i].reshape(1, -1) for part in q_parts)
            t0 = time.time()
            out = self.fhe_circuit_.encrypt_run_decrypt(*sample)
            t1 = time.time()
            fhe_total += (t1 - t0)
            label = int(np.argmax(out.squeeze()))
            fhe_preds.append(label)

        fhe_preds = np.array(fhe_preds)
        fhe_latency = fhe_total / max(1, len(fhe_preds))
        fhe = {
            "accuracy": accuracy_score(y_test, fhe_preds),
            "precision": precision_score(y_test, fhe_preds, average="binary", zero_division=0),
            "recall": recall_score(y_test, fhe_preds, average="binary", zero_division=0),
            "f1_score": f1_score(y_test, fhe_preds, average="binary", zero_division=0),
            "confusion_matrix": confusion_matrix(y_test, fhe_preds).tolist(),
            "total_time_s": fhe_total,
            "num_samples": len(fhe_preds),
            "latency_per_sample_s": fhe_latency,
            "compile_time_s": float(getattr(self, "compile_time_s_", 0.0)),
        }
        return {"plaintext_metrics": plain, "fhe_metrics": fhe}


class MultiInputDecisionTreeClassifier(MultiInputModel, DecisionTreeClassifier):
    """DecisionTree with multi-input compile/eval mixin."""
    pass


class MultiInputsFHEModelDev(FHEModelDev):
    """Save with original DecisionTreeClassifier class for portability."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        model = copy.copy(self.model)
        model.__class__ = DecisionTreeClassifier
        self.model = model


# ============================================================
# Helpers
# ============================================================

def split_by_party_from_parts(X_concat: np.ndarray, parts: List[np.ndarray]) -> Tuple[np.ndarray, ...]:
    sizes = [p.shape[1] for p in parts]
    splits = np.cumsum(sizes)[:-1]
    return tuple(np.hsplit(X_concat, splits))


# ============================================================
# Main
# ============================================================

def main():
    args = parse_args()
    outdir = Path(args.outdir)
    if outdir.exists():
        shutil.rmtree(outdir)
    outdir.mkdir(parents=True, exist_ok=False)

    # 1) Load CSV
    df = pd.read_csv(args.csv)
    if args.target not in df.columns:
        raise ValueError(f"Target column '{args.target}' not found in CSV.")

    # 2) Honor 'split' column if present
    has_split = "split" in df.columns
    if has_split:
        df_train = df[df["split"].astype(str).str.lower() == "train"].copy()
        df_test = df[df["split"].astype(str).str.lower() == "test"].copy()
        if df_train.empty or df_test.empty:
            raise ValueError("Found 'split' column but train/test partitions are empty or invalid.")
        y_train = df_train[args.target].astype(int).to_numpy()
        y_test = df_test[args.target].astype(int).to_numpy()
        X_train_df = df_train.drop(columns=[args.target, "split"])
        X_test_df = df_test.drop(columns=[args.target, "split"])
    else:
        y = df[args.target].astype(int).to_numpy()
        X_df = df.drop(columns=[args.target])
        X_train_df, X_test_df, y_train, y_test = train_test_split(
            X_df, y, test_size=args.test_size, random_state=args.random_state, stratify=y
        )

    # 3) Cast boolean-like columns to int (0/1) for stability
    for X_sub in (X_train_df, X_test_df):
        for col in X_sub.columns:
            vals = X_sub[col].dropna().unique()
            if set(vals).issubset({0, 1, True, False}):
                # Fill missing with 0 (False) before casting
                X_sub[col] = X_sub[col].fillna(0).astype(int)

    # 4) Build per-party preprocessors (only for groups with at least one present column)
    party_order: List[str] = []
    group_columns: Dict[str, Dict[str, List[str]]] = {}
    preprocessors: Dict[str, ColumnTransformer] = {}

    # Determine from the union of train/test columns
    X_all_cols = list(set(X_train_df.columns) | set(X_test_df.columns))

    def intersect_df(df_like: pd.DataFrame, spec: Dict[str, List[str]]) -> Dict[str, List[str]]:
        return {
            "numeric": [c for c in spec.get("numeric", []) if c in X_all_cols],
            "categorical": [c for c in spec.get("categorical", []) if c in X_all_cols],
            "boolean": [c for c in spec.get("boolean", []) if c in X_all_cols],
        }

    for party, spec in KNOWN_FEATURES.items():
        cols = intersect_df(X_train_df, spec)
        if any(cols.values()):
            party_order.append(party)
            group_columns[party] = cols
            preprocessors[party] = build_group_preprocessor(cols)

    if not party_order:
        raise RuntimeError("No known party features found in CSV; update KNOWN_FEATURES to match your columns.")

    # 5) Fit/transform by party
    X_train_parts: List[np.ndarray] = []
    X_test_parts: List[np.ndarray] = []
    preproc_paths: Dict[str, Path] = {}
    per_party_feature_names: Dict[str, List[str]] = {}
    per_party_slices: Dict[str, List[int]] = {}

    offset = 0
    for party in party_order:
        pre = preprocessors[party]
        cols = group_columns[party]["numeric"] + group_columns[party]["categorical"] + group_columns[party]["boolean"]

        X_tr = pre.fit_transform(X_train_df[cols])
        X_te = pre.transform(X_test_df[cols])

        names = safe_feature_names_out(pre, cols)
        width = int(X_tr.shape[1])
        per_party_feature_names[party] = names
        per_party_slices[party] = [offset, offset + width]
        offset += width

        X_train_parts.append(np.asarray(X_tr, dtype=np.float32))
        X_test_parts.append(np.asarray(X_te, dtype=np.float32))

    # Concatenate for model fit
    X_train_concat = np.concatenate(X_train_parts, axis=1)
    X_test_concat = np.concatenate(X_test_parts, axis=1)

    total_width = int(X_train_concat.shape[1])

    # 6) Train DT (balanced & shallow)
    print(f"\nTraining DecisionTree (max_depth={args.max_depth}, class_weight='balanced')...")
    model = MultiInputDecisionTreeClassifier(
        max_depth=args.max_depth,
        class_weight="balanced",
        random_state=args.random_state
    )
    # Fit with fit_benchmark to populate quantizers/_tree_inference
    t0 = time.time()
    model, _ = model.fit_benchmark(X_train_concat, y_train)
    t1 = time.time()
    train_time_s = float(t1 - t0)

    # 7) Compile to FHE as multi-input (time it)
    print(f"Compiling to FHE for parties: {party_order} ...")
    def split_by_party(X_concat: np.ndarray, parts: List[np.ndarray]) -> Tuple[np.ndarray, ...]:
        sizes = [p.shape[1] for p in parts]
        splits = np.cumsum(sizes)[:-1]
        return tuple(np.hsplit(X_concat, splits))

    train_parts_for_compile = split_by_party(X_train_concat, X_train_parts)
    enc_status = ["encrypted"] * len(train_parts_for_compile)

    model.compile(*train_parts_for_compile, inputs_encryption_status=enc_status)
    compile_time_s = float(getattr(model, "compile_time_s_", 0.0))

    # 8) Evaluate with timing
    print("Evaluating on test set (plaintext vs encrypted)...")
    test_parts_for_eval = split_by_party(X_test_concat, X_test_parts)
    results = model.evaluate_with_time(*test_parts_for_eval, y_test=y_test)

    # 9) Save deployment and metadata
    print("\nSaving deployment artifacts to:", outdir)
    fhe_model_dev = MultiInputsFHEModelDev(outdir, model)
    fhe_model_dev.save(via_mlir=True)

    # 10) save preprocessors
    for party, pre in preprocessors.items():
        p_path = outdir / f"preprocessor_{party}.pkl"
        with p_path.open("wb") as f:
            pickle.dump(pre, f)
        preproc_paths[party] = p_path

    # 11) Build 'features' section 
    global_feature_names = []
    for party in party_order:
        global_feature_names.extend([f"{party}:{n}" for n in per_party_feature_names[party]])

    features_section = {
        "party_order": party_order,
        "total_feature_width": total_width,
        "global_feature_names_out": global_feature_names,
        "per_party_features": {
            party: {
                "slice": per_party_slices[party],
                "feature_names_out": per_party_feature_names[party],
            }
            for party in party_order
        }
    }


    report = {
        "parties": party_order,
        "target": args.target,
        "train_size": int(len(y_train)),
        "test_size": int(len(y_test)),
        "max_depth": int(args.max_depth),
        "timing": {
            "train_time_s": train_time_s,
            "compile_time_s": compile_time_s,
            "plaintext_total_time_s": results["plaintext_metrics"]["total_time_s"],
            "plaintext_latency_per_sample_s": results["plaintext_metrics"]["latency_per_sample_s"],
            "fhe_total_time_s": results["fhe_metrics"]["total_time_s"],
            "fhe_num_samples": results["fhe_metrics"]["num_samples"],
            "fhe_latency_per_sample_s": results["fhe_metrics"]["latency_per_sample_s"],
        },
        "metrics": results,
        "group_columns": group_columns,
        "preprocessors": {p: str(path.resolve()) for p, path in preproc_paths.items()},
        "features": features_section,
    }
    with (outdir / "report.json").open("w") as f:
        json.dump(report, f, indent=2)

    print("\nDone.")
    print(json.dumps({
        "timing": report["timing"],
        "plaintext": {
            k: report["metrics"]["plaintext_metrics"][k]
            for k in ("accuracy","precision","recall","f1_score")
        },
        "fhe": {
            k: report["metrics"]["fhe_metrics"][k]
            for k in ("accuracy","precision","recall","f1_score")
        }
    }, indent=2))


if __name__ == "__main__":
    main()
