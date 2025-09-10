
import math, random, json, argparse, hashlib, csv, os
from typing import Dict, Any, Optional

KENYA_COUNTIES = [
    "Mombasa","Kwale","Kilifi","Tana River","Lamu","Taita-Taveta",
    "Garissa","Wajir","Mandera",
    "Marsabit","Isiolo","Meru","Tharaka-Nithi","Embu","Kitui","Machakos","Makueni",
    "Nyandarua","Nyeri","Kirinyaga","Murang'a","Kiambu",
    "Turkana","West Pokot","Samburu","Trans Nzoia","Uasin Gishu","Elgeyo-Marakwet",
    "Nandi","Baringo","Laikipia","Nakuru","Narok","Kajiado","Kericho","Bomet",
    "Kakamega","Vihiga","Bungoma","Busia",
    "Siaya","Kisumu","Homa Bay","Migori","Kisii","Nyamira",
    "Nairobi"
]
print(f"[INFO] Loaded {len(KENYA_COUNTIES)} counties.")

CROPS = [
    "maize","beans","tea","coffee","sugarcane","wheat","rice",
    "potato","sorghum","millet","horticulture","dairy-fodder"
]

TENORS = [3, 6, 9, 12, 18, 24]

DEFAULT_PRICE_MAP = {
    "maize": 35000, "beans": 60000, "tea": 80000, "coffee": 90000,
    "sugarcane": 4000, "wheat": 38000, "rice": 45000, "potato": 25000,
    "sorghum": 32000, "millet": 30000, "horticulture": 70000, "dairy-fodder": 25000
}

DEFAULT_YIELD_PRIORS = {
    "maize": (1.2, 4.0),
    "beans": (0.5, 1.8),
    "tea": (1.0, 3.0),
    "coffee": (0.5, 2.0),
    "sugarcane": (40, 80),
    "wheat": (1.2, 3.5),
    "rice": (1.5, 4.5),
    "potato": (8, 25),
    "sorghum": (0.6, 2.5),
    "millet": (0.6, 2.0),
    "horticulture": (5, 20),
    "dairy-fodder": (5, 20)
}

DEFAULT_PROBS = {
    "prior_default": 0.08,
    "processor_contract": 0.35,
    "insured": 0.25,
    "gov_subsidy": 0.12
}

DEFAULT_RISK_COEFFS = {
    "coef_log_area": -1.2,
    "coef_ndvi": -1.0,
    "coef_tenor_per_year": 0.35,
    "coef_prior_default": 0.9,
    "coef_no_processor": 0.25,
    "coef_interest_rate": 0.02,
    "coef_agritech_score": -0.8,
    "coef_climate_risk": 0.4,
    "coef_input_cost": 0.000004,
    "coef_sales": -0.000001,
    "baseline_p": 0.12,
    "slope_p": 0.55,
    "delta_insured_plus": 0.02,
    "delta_insured_minus": -0.015,
    "delta_processor_contract": -0.02,
    "delta_gov_subsidy": -0.01,
    "delta_prior_default": 0.05,
    "p_min": 0.01,
    "p_max": 0.75
}

def stable_uniform_from_name(name, a, b):
    h = int(hashlib.sha256(name.encode()).hexdigest(), 16)
    rnd = (h % 10_000) / 10_000.0
    return a + (b - a) * rnd

def load_config(path: Optional[str]) -> dict:
    if not path:
        return {}
    with open(path, "r") as f:
        return json.load(f)

def build_county_priors(config):
    priors = {}
    overrides = config.get("county_overrides", {})
    for c in KENYA_COUNTIES:
        mean_rain = stable_uniform_from_name(c, 500, 1400)
        sd_rain = 0.15 * mean_rain
        mean_ndvi = stable_uniform_from_name("ndvi:"+c, 0.35, 0.8)
        sd_ndvi = 0.08
        area_base = stable_uniform_from_name("area:"+c, 0.4, 3.0)
        ov = overrides.get(c, {})
        mean_rain = ov.get("mean_rain", mean_rain)
        sd_rain = ov.get("sd_rain", sd_rain)
        mean_ndvi = ov.get("mean_ndvi", mean_ndvi)
        sd_ndvi = ov.get("sd_ndvi", sd_ndvi)
        area_base = ov.get("area_base", area_base)
        climate_risk = ov.get("climate_risk_index", 1 - (mean_ndvi - 0.35) / (0.8 - 0.35))
        probs = {
            "prior_default": ov.get("prob_prior_default", config.get("probabilities_global", DEFAULT_PROBS).get("prior_default", DEFAULT_PROBS["prior_default"])),
            "processor_contract": ov.get("prob_processor_contract", config.get("probabilities_global", DEFAULT_PROBS).get("processor_contract", DEFAULT_PROBS["processor_contract"])),
            "insured": ov.get("prob_insured", config.get("probabilities_global", DEFAULT_PROBS).get("insured", DEFAULT_PROBS["insured"])),
            "gov_subsidy": ov.get("prob_gov_subsidy", config.get("probabilities_global", DEFAULT_PROBS).get("gov_subsidy", DEFAULT_PROBS["gov_subsidy"])),
        }
        priors[c] = dict(mean_rain=mean_rain, sd_rain=sd_rain,
                         mean_ndvi=mean_ndvi, sd_ndvi=sd_ndvi,
                         area_base=area_base,
                         climate_risk_index=climate_risk,
                         probs=probs)
    return priors

def get_price_map(config):
    m = dict(DEFAULT_PRICE_MAP)
    m.update(config.get("price_map_override", {}))
    return m

def get_yield_priors(config):
    yp = dict(DEFAULT_YIELD_PRIORS)
    yp.update(config.get("crop_yield_priors_global_override", {}))
    per_county_mult = config.get("yield_multipliers_by_county", {})
    return yp, per_county_mult

def get_risk_coeffs(config):
    rc = dict(DEFAULT_RISK_COEFFS)
    rc.update(config.get("risk_coefficients", {}))
    return rc

def sample_rain_ndvi(p):
    import random as _r
    rain = max(50, _r.gauss(p["mean_rain"], p["sd_rain"]))
    ndvi = min(0.95, max(0.05, _r.gauss(p["mean_ndvi"], p["sd_ndvi"])))
    return rain, ndvi

def sample_crop_primary():
    weights = [0.28 if c=="maize" else 0.72/(len(CROPS)-1) for c in CROPS]
    return random.choices(CROPS, weights=weights, k=1)[0]

def sigmoid(x): return 1/(1+math.exp(-x))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2500)
    ap.add_argument("--seed", type=int, default=123)
    ap.add_argument("--test_frac", type=float, default=0.2)
    ap.add_argument("--out", type=str, default="kenya_agri_synthetic_tuned.csv")
    ap.add_argument("--config", type=str, default=None)
    args = ap.parse_args()
    random.seed(args.seed)

    config = load_config(args.config)
    county_priors = build_county_priors(config)
    price_map = get_price_map(config)
    yield_priors_global, yield_mults = get_yield_priors(config)
    risk_coeffs = get_risk_coeffs(config)

    rows = []
    for i in range(args.n):
        county = random.choice(KENYA_COUNTIES)
        p = county_priors[county]
        base = p["area_base"]
        noise = random.lognormvariate(0, 0.45)
        area = max(0.1, base*noise)

        crop1 = sample_crop_primary()
        crop2 = sample_crop_primary() if random.random() < 0.35 else ""

        rain, ndvi = sample_rain_ndvi(p)
        climate_risk = p["climate_risk_index"]
        irrig = random.random() < 0.18
        soil_q = min(1.0, max(0.0, random.gauss(0.55 + 0.2*(ndvi-0.5), 0.1)))

        lo, hi = yield_priors_global.get(crop1, (1.0, 2.0))
        mult = yield_mults.get(county, {}).get(crop1, 1.0)
        lo, hi = lo*mult, hi*mult
        climate_factor = 0.6*ndvi + 0.4*min(1.5, rain/1000.0)
        u = max(0, min(1, random.gauss(climate_factor, 0.12)))
        y_t_ha = max(0.01, lo + (hi-lo)*u)
        if area < 0.5:
            y_t_ha *= random.uniform(0.8, 1.1)

        sales = max(0, y_t_ha*area*price_map.get(crop1, 40000) * random.uniform(0.85,1.15))
        input_cost = abs(random.gauss(35000 * area, 12000))
        mpesa_txn = max(0, int(random.gauss(45, 20)))
        mpesa_in = max(0, random.gauss(120000, 80000))

        prob = p["probs"]
        prior_def = random.random() < prob["prior_default"]
        processor_contract = random.random() < prob["processor_contract"]
        insured = random.random() < prob["insured"]
        gov_subsidy = random.random() < prob["gov_subsidy"]

        agritech_score = min(1.0, max(0.0, random.gauss(0.55 + 0.2*(ndvi-0.5) + (0.05 if processor_contract else 0), 0.12)))
        loan_amount = max(10000, random.gauss(0.35*sales + 25000, 40000))
        tenor = random.choice(TENORS)
        interest_rate = max(8.0, min(28.0, random.gauss(18.0, 4.0)))

        rc = risk_coeffs
        z = (
            rc["coef_log_area"]*math.log1p(area) +
            rc["coef_ndvi"]*(ndvi-0.6) +
            rc["coef_tenor_per_year"]*(tenor/12.0) +
            (rc["coef_prior_default"] if prior_def else 0) +
            (rc["coef_no_processor"] if not processor_contract else -0.0) +
            rc["coef_interest_rate"]*(interest_rate-18.0) +
            rc["coef_agritech_score"]*(agritech_score-0.5) +
            rc["coef_climate_risk"]*(climate_risk-0.5) +
            rc["coef_input_cost"]*(input_cost-40000) +
            rc["coef_sales"]*(sales-150000)
        )
        risk_score_internal = sigmoid(z)

        base_p = rc["baseline_p"] + rc["slope_p"]*(risk_score_internal - 0.5)
        if insured:
            base_p += rc["delta_insured_plus"]
            base_p += rc["delta_insured_minus"]
        if processor_contract:
            base_p += rc["delta_processor_contract"]
        if gov_subsidy:
            base_p += rc["delta_gov_subsidy"]
        if prior_def:
            base_p += rc["delta_prior_default"]
        p_event = max(rc["p_min"], min(rc["p_max"], base_p))
        target = random.random() < p_event

        rows.append({
            "record_id": f"rec_{i:07d}",
            "farmer_id": f"farmer_{random.randint(1,2_000_000):07d}",
            "county": county,
            "sub_county": "",
            "farm_area_ha": round(area,3),
            "crop_primary": crop1,
            "crop_secondary": crop2,
            "rain_mm_gs": round(rain,1),
            "eo_ndvi_gs": round(ndvi,3),
            "irrigated": irrig,
            "soil_quality_index": round(soil_q,3),
            "input_cost_kes": round(input_cost,0),
            "sales_kes": round(sales,0),
            "yield_t_ha": round(y_t_ha,3),
            "mpesa_txn_count_90d": mpesa_txn,
            "mpesa_inflow_kes_90d": round(mpesa_in,0),
            "prior_default": prior_def,
            "processor_contract": processor_contract,
            "insured": insured,
            "agritech_score": round(agritech_score,3),
            "gov_subsidy": gov_subsidy,
            "loan_amount_kes": round(loan_amount,0),
            "tenor_months": tenor,
            "interest_rate_pct": round(interest_rate,2),
            "climate_risk_index": round(climate_risk,3),
            "risk_score_internal": round(risk_score_internal,3),
            "default_or_claim": target
        })

    idxs = list(range(len(rows)))
    random.shuffle(idxs)
    cutoff = int((1 - args.test_frac) * len(rows))
    train_idx = set(idxs[:cutoff])

    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) + ["split"])
        writer.writeheader()
        for i, r in enumerate(rows):
            r2 = dict(r)
            r2["split"] = "train" if i in train_idx else "test"
            writer.writerow(r2)

    print(f"[OK] Wrote {args.out} with {len(rows)} rows. "
          f"Config used: {os.path.abspath(args.config) if args.config else '(defaults)'}")

if __name__ == "__main__":
    main()
