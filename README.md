# Minor-project-of-cyber-security
 Cybersecurity Risk Assessment Framework for Small Businesses •

"""
SME Cybersecurity Risk Assessment Tool
======================================
Minor Project - Cybersecurity Risk Assessment Framework for Small Businesses

What this program does
----------------------
1. Asks a few questions about a small/medium business (its "profile").
2. Asks which security controls the business already has (NIST CSF 2.0 based).
3. Scores 10 common SME cyber threats using:
       Inherent risk  = Likelihood (1-5) x Impact (1-5)
       Residual risk  = Inherent risk x (1 - control effectiveness)
4. Ranks the threats, rates the overall security posture,
   and recommends the best-value controls to add next.
5. Can run 3 built-in case studies and export results to CSV.

How to run (only Python 3.8+ needed, no extra libraries):
    python sme_risk_tool.py                  -> menu
    python sme_risk_tool.py --interactive    -> assess your own business
    python sme_risk_tool.py --case-studies   -> run the 3 sample businesses
    python sme_risk_tool.py --case-studies --csv results.csv
"""

import argparse
import csv

# ----------------------------------------------------------------------
# 1. DATA: security controls
#    Each control belongs to one NIST CSF 2.0 function and has a cost level.
# ----------------------------------------------------------------------
COST_SCORE = {"Low": 1, "Medium": 2, "High": 3}

CONTROLS = {
    "C01": {"name": "Multi-factor authentication (MFA) on email and key accounts", "nist": "Protect", "cost": "Low"},
    "C02": {"name": "Strong password policy / password manager", "nist": "Protect", "cost": "Low"},
    "C03": {"name": "Regular employee security-awareness training", "nist": "Protect", "cost": "Low"},
    "C04": {"name": "Regular software patching and updates", "nist": "Protect", "cost": "Low"},
    "C05": {"name": "Antivirus / endpoint protection on all devices", "nist": "Protect", "cost": "Low"},
    "C06": {"name": "Firewall and basic network segmentation", "nist": "Protect", "cost": "Medium"},
    "C07": {"name": "Regular, tested, offline/off-site backups", "nist": "Recover", "cost": "Medium"},
    "C08": {"name": "Least-privilege access control (staff only access what they need)", "nist": "Protect", "cost": "Low"},
    "C09": {"name": "Email spam / phishing filtering", "nist": "Protect", "cost": "Low"},
    "C10": {"name": "Encryption of laptops, drives and sensitive files", "nist": "Protect", "cost": "Low"},
    "C11": {"name": "Logging and monitoring of systems and logins", "nist": "Detect", "cost": "Medium"},
    "C12": {"name": "Written incident response plan", "nist": "Respond", "cost": "Low"},
    "C13": {"name": "Security review of vendors / third parties", "nist": "Govern", "cost": "Low"},
    "C14": {"name": "Written security policy with a named responsible person", "nist": "Govern", "cost": "Low"},
    "C15": {"name": "Inventory of devices, software and data", "nist": "Identify", "cost": "Low"},
    "C16": {"name": "Secure cloud configuration and sharing settings review", "nist": "Protect", "cost": "Low"},
    "C17": {"name": "Device management with remote lock/wipe", "nist": "Protect", "cost": "Medium"},
}

NIST_FUNCTIONS = ["Govern", "Identify", "Protect", "Detect", "Respond", "Recover"]

# ----------------------------------------------------------------------
# 2. DATA: threats
#    base_l / base_i are the default Likelihood and Impact (1-5) for a typical SME.
#    "controls" maps a control ID to its weight (how much it reduces THIS threat
#    when fully implemented, 0-1).
# ----------------------------------------------------------------------
THREATS = [
    {"id": "T01", "name": "Phishing and business email compromise",
     "base_l": 4, "base_i": 4,
     "controls": {"C03": 0.35, "C09": 0.30, "C01": 0.30, "C05": 0.10}},
    {"id": "T02", "name": "Ransomware",
     "base_l": 3, "base_i": 5,
     "controls": {"C07": 0.45, "C04": 0.20, "C05": 0.20, "C09": 0.15, "C06": 0.10, "C12": 0.10}},
    {"id": "T03", "name": "Weak or reused passwords / account takeover",
     "base_l": 4, "base_i": 4,
     "controls": {"C01": 0.45, "C02": 0.35, "C11": 0.10}},
    {"id": "T04", "name": "Insider threat (negligent or malicious staff)",
     "base_l": 3, "base_i": 4,
     "controls": {"C08": 0.35, "C03": 0.20, "C11": 0.20, "C14": 0.10}},
    {"id": "T05", "name": "Unpatched software and known vulnerabilities",
     "base_l": 4, "base_i": 3,
     "controls": {"C04": 0.50, "C06": 0.15, "C05": 0.10, "C15": 0.15}},
    {"id": "T06", "name": "Lost or stolen devices",
     "base_l": 3, "base_i": 3,
     "controls": {"C10": 0.45, "C17": 0.35, "C02": 0.10}},
    {"id": "T07", "name": "Third-party / vendor and supply-chain compromise",
     "base_l": 3, "base_i": 4,
     "controls": {"C13": 0.40, "C08": 0.15, "C14": 0.10}},
    {"id": "T08", "name": "Cloud misconfiguration and accidental data exposure",
     "base_l": 3, "base_i": 4,
     "controls": {"C16": 0.45, "C08": 0.20, "C10": 0.15, "C11": 0.10}},
    {"id": "T09", "name": "Data breach and legal non-compliance (e.g. DPDP Act 2023)",
     "base_l": 3, "base_i": 5,
     "controls": {"C10": 0.25, "C08": 0.20, "C11": 0.20, "C14": 0.15, "C12": 0.10}},
    {"id": "T10", "name": "Malware and website / network attacks",
     "base_l": 3, "base_i": 3,
     "controls": {"C05": 0.40, "C04": 0.20, "C06": 0.20}},
]

# ----------------------------------------------------------------------
# 3. DATA: business profile questions and how each answer changes the scores
#    ("l" = adds +1 to Likelihood, "i" = adds +1 to Impact for those threats)
# ----------------------------------------------------------------------
PROFILE_QUESTIONS = {
    "sensitive_data": "Do you store sensitive personal, medical or financial data of customers?",
    "online_payments": "Do you accept online / digital payments (UPI, cards, net banking)?",
    "remote_work": "Do staff work remotely or use personal devices for work?",
    "uses_cloud": "Do you use cloud services (Google Workspace, Microsoft 365, cloud software)?",
    "relies_on_vendors": "Do you depend on outside vendors with access to your systems or data?",
    "critical_uptime": "Would a few days of downtime seriously hurt the business?",
    "many_employees": "Do you have more than 20 employees?",
}

PROFILE_MODIFIERS = {
    "sensitive_data": [("T04", "i"), ("T08", "i"), ("T09", "i")],
    "online_payments": [("T01", "l"), ("T03", "l"), ("T10", "l")],
    "remote_work": [("T03", "l"), ("T06", "l")],
    "uses_cloud": [("T03", "l"), ("T08", "l")],
    "relies_on_vendors": [("T07", "l")],
    "critical_uptime": [("T02", "i"), ("T10", "i")],
    "many_employees": [("T04", "l")],
}

# ----------------------------------------------------------------------
# 4. SETTINGS
# ----------------------------------------------------------------------
MAX_EFFECTIVENESS = 0.85   # no set of controls removes risk completely
ANSWER_VALUE = {"y": 1.0, "p": 0.5, "n": 0.0}   # yes / partly / no


def risk_band(score):
    """Band for a single threat (score out of 25)."""
    if score < 5:
        return "Low"
    if score < 10:
        return "Medium"
    if score < 17:
        return "High"
    return "Critical"


def posture_band(index):
    """Band for the overall Risk Index (0-100)."""
    if index < 20:
        return "Low risk (strong posture)"
    if index < 35:
        return "Moderate risk"
    if index < 45:
        return "High risk"
    return "Critical risk (weak posture)"


# ----------------------------------------------------------------------
# 5. CORE MODEL
# ----------------------------------------------------------------------
def clamp(value, low=1, high=5):
    return max(low, min(high, value))


def adjusted_scores(threat, profile):
    """Start from the base Likelihood/Impact and apply the profile modifiers."""
    likelihood, impact = threat["base_l"], threat["base_i"]
    for question, changes in PROFILE_MODIFIERS.items():
        if profile.get(question):
            for threat_id, kind in changes:
                if threat_id == threat["id"]:
                    if kind == "l":
                        likelihood += 1
                    else:
                        impact += 1
    return clamp(likelihood), clamp(impact)


def control_effectiveness(threat, answers):
    """
    Combine the controls that protect against a threat.
    Each control removes a share of the remaining risk:
        effectiveness = 1 - (1 - w1*a1) * (1 - w2*a2) * ...
    where w = weight of the control and a = how well it is implemented (0, 0.5, 1).
    """
    remaining = 1.0
    for control_id, weight in threat["controls"].items():
        remaining *= 1 - weight * answers.get(control_id, 0.0)
    return min(1 - remaining, MAX_EFFECTIVENESS)


def assess(profile, answers):
    """Score every threat. Returns (results sorted by residual risk, summary dict)."""
    results = []
    for threat in THREATS:
        likelihood, impact = adjusted_scores(threat, profile)
        inherent = likelihood * impact
        effectiveness = control_effectiveness(threat, answers)
        residual = inherent * (1 - effectiveness)
        results.append({
            "id": threat["id"], "name": threat["name"],
            "likelihood": likelihood, "impact": impact,
            "inherent": inherent, "inherent_band": risk_band(inherent),
            "effectiveness": effectiveness,
            "residual": residual, "residual_band": risk_band(residual),
        })
    results.sort(key=lambda r: r["residual"], reverse=True)

    max_total = 25 * len(THREATS)
    inherent_total = sum(r["inherent"] for r in results)
    residual_total = sum(r["residual"] for r in results)
    summary = {
        "inherent_index": inherent_total / max_total * 100,
        "risk_index": residual_total / max_total * 100,
        "posture": posture_band(residual_total / max_total * 100),
        "nist": nist_maturity(answers),
    }
    return results, summary


def nist_maturity(answers):
    """Average implementation (0-100%) of controls under each NIST CSF function."""
    scores = {}
    for function in NIST_FUNCTIONS:
        ids = [cid for cid, c in CONTROLS.items() if c["nist"] == function]
        scores[function] = (sum(answers.get(cid, 0.0) for cid in ids) / len(ids) * 100) if ids else None
    return scores


def recommend(profile, answers, top_n=5):
    """
    Rank controls that are not fully in place by 'value for money':
        value = total drop in residual risk if fully implemented / cost score
    """
    _, base = assess(profile, answers)
    base_total = base["risk_index"]
    ranked = []
    for control_id, control in CONTROLS.items():
        if answers.get(control_id, 0.0) >= 1.0:
            continue
        trial = dict(answers)
        trial[control_id] = 1.0
        _, after = assess(profile, trial)
        drop = base_total - after["risk_index"]
        if drop > 0:
            ranked.append({
                "id": control_id, "name": control["name"], "cost": control["cost"],
                "nist": control["nist"], "index_drop": drop,
                "value": drop / COST_SCORE[control["cost"]],
            })
    ranked.sort(key=lambda r: r["value"], reverse=True)
    return ranked[:top_n]


def simulate_mitigation(profile, answers, top_n=5):
    """Apply the top-N recommended controls and re-score. Used for before/after tables."""
    picks = recommend(profile, answers, top_n)
    improved = dict(answers)
    for pick in picks:
        improved[pick["id"]] = 1.0
    results, summary = assess(profile, improved)
    return picks, results, summary


# ----------------------------------------------------------------------
# 6. CASE STUDIES (three sample small businesses)
# ----------------------------------------------------------------------
CASE_STUDIES = {
    "Sharma General Store (retail shop, 6 staff)": {
        "profile": {"online_payments": True, "critical_uptime": True},
        "answers": {"C05": 1.0, "C02": 0.5, "C07": 0.5},
    },
    "CarePlus Clinic (healthcare, 12 staff)": {
        "profile": {"sensitive_data": True, "online_payments": True, "uses_cloud": True,
                    "relies_on_vendors": True, "critical_uptime": True},
        "answers": {"C05": 1.0, "C06": 1.0, "C07": 1.0, "C04": 0.5, "C10": 0.5,
                    "C08": 0.5, "C02": 0.5, "C09": 0.5},
    },
    "Verma & Associates (accounting firm, 25 staff)": {
        "profile": {"sensitive_data": True, "online_payments": True, "remote_work": True,
                    "uses_cloud": True, "relies_on_vendors": True, "many_employees": True},
        "answers": {"C01": 0.5, "C02": 1.0, "C03": 0.5, "C04": 1.0, "C05": 1.0,
                    "C07": 1.0, "C09": 1.0, "C06": 1.0, "C08": 0.5, "C10": 0.5, "C14": 0.5},
    },
}


# ----------------------------------------------------------------------
# 7. INPUT / OUTPUT HELPERS
# ----------------------------------------------------------------------
def ask(prompt, allowed):
    """Keep asking until the user types one of the allowed answers."""
    while True:
        reply = input(prompt).strip().lower()
        if reply in allowed:
            return reply
        print(f"   Please type one of: {', '.join(allowed)}")


def interactive_input():
    print("\n--- Part 1: About your business (y = yes, n = no) ---")
    profile = {key: ask(f"{q} [y/n]: ", ["y", "n"]) == "y" for key, q in PROFILE_QUESTIONS.items()}
    print("\n--- Part 2: Security controls (y = yes, p = partly, n = no) ---")
    answers = {}
    for control_id, control in CONTROLS.items():
        reply = ask(f"[{control['nist']}] {control['name']}? [y/p/n]: ", list(ANSWER_VALUE))
        answers[control_id] = ANSWER_VALUE[reply]
    return profile, answers


def print_report(title, profile, answers):
    results, summary = assess(profile, answers)
    line = "=" * 78
    print(f"\n{line}\nRISK ASSESSMENT: {title}\n{line}")
    print(f"Overall Risk Index : {summary['risk_index']:.1f} / 100  ->  {summary['posture']}")
    print(f"(Before any controls it would be {summary['inherent_index']:.1f} / 100)\n")

    print("NIST CSF 2.0 control coverage:")
    for function, value in summary["nist"].items():
        bar = "#" * int((value or 0) / 5)
        print(f"  {function:<9} {value:5.0f}%  {bar}")

    print("\nThreats ranked by residual risk:")
    print(f"  {'#':<3}{'Threat':<58}{'L':>2} {'I':>2} {'Inh':>5} {'Res':>5}  Band")
    for rank, r in enumerate(results, 1):
        print(f"  {rank:<3}{r['name'][:56]:<58}{r['likelihood']:>2} {r['impact']:>2} "
              f"{r['inherent']:>5.0f} {r['residual']:>5.1f}  {r['residual_band']}")

    print("\nTop recommended controls (best risk reduction per unit cost):")
    picks, _, after = simulate_mitigation(profile, answers)
    for i, p in enumerate(picks, 1):
        print(f"  {i}. {p['name']}  [{p['nist']}, cost: {p['cost']}, "
              f"index -{p['index_drop']:.1f}]")
    print(f"\nIf all five are implemented, the Risk Index falls from "
          f"{summary['risk_index']:.1f} to {after['risk_index']:.1f}.")
    return results, summary


def export_csv(path, rows):
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nResults saved to {path}")


def run_case_studies(csv_path=None):
    rows = []
    for name, case in CASE_STUDIES.items():
        results, _ = print_report(name, case["profile"], case["answers"])
        for r in results:
            rows.append({"business": name, "threat_id": r["id"], "threat": r["name"],
                         "likelihood": r["likelihood"], "impact": r["impact"],
                         "inherent_risk": r["inherent"], "control_effectiveness": round(r["effectiveness"], 2),
                         "residual_risk": round(r["residual"], 1), "band": r["residual_band"]})
    if csv_path:
        export_csv(csv_path, rows)


def main():
    parser = argparse.ArgumentParser(description="SME Cybersecurity Risk Assessment Tool")
    parser.add_argument("--interactive", action="store_true", help="assess your own business")
    parser.add_argument("--case-studies", action="store_true", help="run the built-in case studies")
    parser.add_argument("--csv", metavar="FILE", help="save case study results to a CSV file")
    args = parser.parse_args()

    if args.case_studies:
        run_case_studies(args.csv)
    elif args.interactive:
        profile, answers = interactive_input()
        print_report("Your business", profile, answers)
    else:
        print("SME Cybersecurity Risk Assessment Tool")
        print("  1) Assess my business")
        print("  2) Run the case studies")
        choice = ask("Choose 1 or 2: ", ["1", "2"])
        if choice == "1":
            profile, answers = interactive_input()
            print_report("Your business", profile, answers)
        else:
            run_case_studies(args.csv)


if __name__ == "__main__":
    main()
