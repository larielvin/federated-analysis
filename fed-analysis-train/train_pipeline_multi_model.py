#!/usr/bin/env python3
"""
Extended benchmarking pipeline (FHE execute compulsory) for Kenyan agri-finance synthetic data.

Models compared:
  Plaintext (scikit-learn / xgboost):
    - Logistic Regression
    - Linear SVM (LinearSVC)
    - Decision Tree (shallow)
    - Random Forest (shallow)
    - XGBoost (optional if installed)

  Concrete-ML (quantized, FHE-capable):
    - Logistic Regression
    - Linear SVM
    - Decision Tree
    - Random Forest
    - XGBoost (optional if installed)
    - Quantized Neural Net (small MLP, QAT)

For each Concrete-ML model we report:
  - clear-quantized
  - FHE simulate
  - FHE execute (REAL encrypted inference; compulsory)

Artifacts:
  - preprocessor.pkl
  - sklearn_*.joblib (plaintext models)
  - concrete_*_cml.pkl (only LR, LinearSVM, QNN — tree models skipped)
  - metrics_all.json

"""

import argparse
import json
import os
import pickle
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression as SkLR
from sklearn.metrics import (accuracy_score, roc_auc_score,
                             precision_recall_fscore_support, confusion_matrix)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.svm import LinearSVC as SkLinearSVC
from sklearn.tree import DecisionTreeClassifier as SkDecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier as SkRandomForestClassifier
from sklearn.utils.class_weight import compute_class_weight

# Optional XGBoost baseline
try:
    from xgboost import XGBClassifier as SkXGBClassifier
    HAS_XGB = True
except Exception:
    HAS_XGB = False

# Concrete-ML imports
from concrete.ml.sklearn import LogisticRegression as CMLLogReg
from concrete.ml.sklearn.svm import LinearSVC as CMLLinearSVC
from concrete.ml.sklearn.tree import DecisionTreeClassifier as CMLDecisionTreeClassifier
from concrete.ml.sklearn.rf import RandomForestClassifier as CMLRandomForestClassifier
from concrete.ml.sklearn.xgb import XGBClassifier as CMLXGBClassifier
from concrete.ml.sklearn import NeuralNetClassifier as CMLNeuralNetClassifier

import torch.nn as nn


@dataclass
class FeatureSpec:
    numeric: List[str]
    categorical: List[str]
    boolean: List[str]


def infer_feature_spec(df: pd.DataFrame, target: str) -> FeatureSpec:
    candidate_num = [
        "farm_area_ha", "rain_mm_gs", "eo_ndvi_gs", "soil_quality_index",
        "input_cost_kes", "sales_kes", "yield_t_ha",
        "mpesa_txn_count_90d", "mpesa_inflow_kes_90d",
        "agritech_score", "loan_amount_kes", "tenor_months",
        "interest_rate_pct", "climate_risk_index"
    ]
    candidate_cat = ["county", "crop_primary", "crop_secondary"]
    candidate_bool = ["irrigated", "prior_default", "processor_contract", "insured", "gov_subsidy"]

    numeric = [c for c in candidate_num if c in df.columns and c != target]
    categorical = [c for c in candidate_cat if c in df.columns and c != target]
    boolean = [c for c in candidate_bool if c in df.columns and c != target]

    # Cast booleans to int upfront
    for b in boolean:
        if b in df.columns:
            df[b] = df[b].astype(int)

    return FeatureSpec(numeric, categorical, boolean)


def build_preprocessor(spec: FeatureSpec) -> ColumnTransformer:
    numeric_pipe = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler(with_mean=True, with_std=True)),
    ])
    categorical_pipe = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("ohe", OneHotEncoder(handle_unknown="ignore", sparse=False)),
    ])
    # Boolean passthrough (already int)
    boolean_pipe = "passthrough"

    pre = ColumnTransformer(
        transformers=[
            ("num", numeric_pipe, spec.numeric),
            ("cat", categorical_pipe, spec.categorical),
            ("bool", boolean_pipe, spec.boolean),
        ],
        remainder="drop",
        sparse_threshold=0.0,
    )
    return pre


def to_numpy(pre: ColumnTransformer, dfX: pd.DataFrame) -> np.ndarray:
    X = pre.transform(dfX)
    return np.asarray(X, dtype=np.float32)


def evaluate_binary(y_true: np.ndarray, y_pred: np.ndarray, y_score: Optional[np.ndarray], label: str) -> dict:
    acc = accuracy_score(y_true, y_pred)
    prec, rec, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    cm = confusion_matrix(y_true, y_pred).tolist()
    out = {"label": label, "accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "confusion_matrix": cm}
    if y_score is not None:
        try:
            out["roc_auc"] = roc_auc_score(y_true, y_score)
        except Exception:
            pass
    return out


def evaluate_with_time(predict_fn, X: np.ndarray, y_true: np.ndarray, label: str,
                       score_fn=None) -> dict:
    n = len(X)
    t0 = time.time()
    y_pred = predict_fn(X)
    t1 = time.time()
    elapsed = t1 - t0
    latency = elapsed / max(1, n)

    y_score = None
    if score_fn is not None:
        try:
            y_score = score_fn(X)
        except Exception:
            y_score = None

    metrics = evaluate_binary(y_true, y_pred, y_score, label)
    metrics["total_time_s"] = elapsed
    metrics["num_samples"] = n
    metrics["latency_per_sample_s"] = latency
    return metrics


def train_eval_concrete_model(name: str, model,
                              X_train, y_train,
                              X_test, y_test,
                              outdir: Path,
                              execute_all: bool,
                              execute_samples: int,
                              pickle_safe: bool = True,
                              sk_model=None) -> Dict[str, dict]:
    """
    Train/evaluate Concrete-ML model (clear, simulate, execute).
    Optionally: also train/evaluate sklearn plaintext equivalent if sk_model is given.
    """
    out: Dict[str, dict] = {}

    # -------- sklearn baseline (if provided) --------
    if sk_model is not None:
        sk_model.fit(X_train, y_train)

        try:
            joblib.dump(sk_model, outdir / f"{name}_sklearn.joblib")
        except Exception as e:
            print(f"[WARN] Could not save sklearn model {name}: {e}")

        out[f"{name}_sklearn_plaintext"] = evaluate_with_time(
            sk_model.predict,
            X_test, y_test,
            f"{name}_sklearn_plaintext",
            score_fn=(
                (lambda X: sk_model.predict_proba(X)[:, 1]) if hasattr(sk_model, "predict_proba")
                else (lambda X: sk_model.decision_function(X)) if hasattr(sk_model, "decision_function")
                else None
            ),
        )

    # -------- Concrete-ML model --------
    model.fit(X_train, y_train)

    if pickle_safe:
        try:
            with open(outdir / f"{name}_cml.pkl", "wb") as f:
                pickle.dump(model, f)
        except Exception as e:
            print(f"[WARN] Could not pickle {name} model: {e}. Skipping save.")

    # Clear-quantized
    out[f"{name}_clear_quantized"] = evaluate_with_time(
        model.predict,
        X_test, y_test,
        f"{name}_clear_quantized",
        score_fn=(lambda X: model.predict_proba(X)[:, 1]) if hasattr(model, "predict_proba") else None
    )

    # Compile
    t0 = time.time()
    model.compile(X_test)
    out[f"{name}_compile_time_s"] = time.time() - t0

    # FHE simulate
    out[f"{name}_fhe_simulate"] = evaluate_with_time(
        lambda X: model.predict(X, fhe="simulate"),
        X_test, y_test,
        f"{name}_fhe_simulate",
        score_fn=(lambda X: model.predict_proba(X, fhe="simulate")[:, 1]) if hasattr(model, "predict_proba") else None
    )

    # FHE execute (compulsory)
    if execute_all:
        subset, y_true_subset, subset_label = X_test, y_test, f"all_{len(X_test)}"
    else:
        k = max(1, min(execute_samples, len(X_test)))
        subset, y_true_subset, subset_label = X_test[:k], y_test[:k], f"subset_{k}"

    exec_metrics = evaluate_with_time(
        lambda X: model.predict(X, fhe="execute"),
        subset, y_true_subset,
        f"{name}_fhe_execute_{subset_label}",
        score_fn=None
    )
    exec_metrics["compile_time_s"] = out[f"{name}_compile_time_s"]
    out[f"{name}_fhe_execute"] = exec_metrics

    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="kenya_agri.csv", help="Path to synthetic CSV")
    ap.add_argument("--target", default="default_or_claim", help="Target column name")
    ap.add_argument("--outdir", default="artifacts_multi", help="Output directory")
    ap.add_argument("--n_bits", type=int, default=8, help="Quantization bits for Concrete-ML")
    ap.add_argument("--execute_all", type=str, default="false")
    ap.add_argument("--execute_samples", type=int, default=64)
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # Load
    df = pd.read_csv(args.csv)
    if args.target not in df.columns:
        raise ValueError(f"Target '{args.target}' not in CSV")

    # Honour split if present
    if "split" in df.columns:
        train_df = df[df["split"] == "train"].copy()
        test_df = df[df["split"] == "test"].copy()
    else:
       train_df, test_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df[args.target])

    # Features
    spec = infer_feature_spec(train_df, target=args.target)
    pre = build_preprocessor(spec)
    pre.fit(train_df[spec.numeric + spec.categorical + spec.boolean])

    with open(outdir / "preprocessor.pkl", "wb") as f:
        pickle.dump({"preprocessor": pre, "feature_spec": spec}, f)

    X_train = to_numpy(pre, train_df[spec.numeric + spec.categorical + spec.boolean])
    X_test = to_numpy(pre, test_df[spec.numeric + spec.categorical + spec.boolean])
    y_train = train_df[args.target].astype(int).to_numpy()
    y_test = test_df[args.target].astype(int).to_numpy()

    execute_all = str(args.execute_all).lower() in {"true", "1", "yes", "y"}
    results: Dict[str, dict] = {}


    # Logistic Regression
    results["logreg"] = train_eval_concrete_model(
        "logreg",
        CMLLogReg(n_bits=args.n_bits, fit_intercept=True, max_iter=2000, class_weight="balanced"),
        X_train, y_train, X_test, y_test,
        outdir, execute_all, args.execute_samples,
        pickle_safe=True,
        sk_model=SkLR(max_iter=2000, class_weight="balanced")
    )

    # Linear SVM
    results["linear_svm"] = train_eval_concrete_model(
        "linear_svm",
        CMLLinearSVC(n_bits=args.n_bits, max_iter=5000, class_weight="balanced"),
        X_train, y_train, X_test, y_test,
        outdir, execute_all, args.execute_samples,
        pickle_safe=True,
        sk_model=SkLinearSVC(max_iter=5000, class_weight="balanced")
    )

    # Decision Tree
    results["decision_tree"] = train_eval_concrete_model(
        "decision_tree",
        CMLDecisionTreeClassifier(max_depth=3, class_weight="balanced", n_bits=args.n_bits),
        X_train, y_train, X_test, y_test,
        outdir, execute_all, args.execute_samples,
        pickle_safe=False,
        sk_model=SkDecisionTreeClassifier(max_depth=3, class_weight="balanced")
    )

    # Random Forest
    results["random_forest"] = train_eval_concrete_model(
        "random_forest",
        CMLRandomForestClassifier(n_estimators=10, max_depth=3, class_weight="balanced", n_bits=args.n_bits),
        X_train, y_train, X_test, y_test,
        outdir, execute_all, args.execute_samples,
        pickle_safe=False,
        sk_model=SkRandomForestClassifier(n_estimators=10, max_depth=3, class_weight="balanced")
    )

    # XGBoost
    if HAS_XGB:
        results["xgboost"] = train_eval_concrete_model(
            "xgboost",
            CMLXGBClassifier(n_estimators=10, max_depth=3, n_bits=args.n_bits),
            X_train, y_train, X_test, y_test,
            outdir, execute_all, args.execute_samples,
            pickle_safe=False,
            sk_model=SkXGBClassifier(n_estimators=10, max_depth=3, use_label_encoder=False, eval_metric="logloss")
        )
    else:
        results["xgboost"] = {"skipped": True}

    # QNN (safe to pickle)
    qnn_params = dict(
        module__n_layers=2,
        module__activation_function=nn.ReLU,
        module__n_hidden_neurons_multiplier=2,
        module__n_w_bits=3,       # quantization bits for weights
        module__n_a_bits=3,       # quantization bits for activations
        module__n_accum_bits=6,   # quantization bits for accumulators > n_w_bits + n_a_bits (or slightly larger).
        max_epochs=5,
        verbose=0,
    )
    cml_qnn = CMLNeuralNetClassifier(**qnn_params)
    results["concrete_qnn"] = train_eval_concrete_model(
        "concrete_qnn", cml_qnn, X_train, y_train, X_test, y_test, outdir, execute_all, args.execute_samples, pickle_safe=True
    )

    with open(outdir / "metrics_all.json", "w") as f:
        json.dump(results, f, indent=2)

    print("[Summary]")
    print(json.dumps({k: list(v.keys()) for k, v in results.items() if isinstance(v, dict)}, indent=2))
    print(f"\nArtifacts in: {outdir.resolve()}")


if __name__ == "__main__":
    main()
