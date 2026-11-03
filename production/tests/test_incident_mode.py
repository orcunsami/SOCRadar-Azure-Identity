#!/usr/bin/env python3
"""IncidentMode: the incident path that shows in the Microsoft Defender portal.

Learn: "Incidents created in Microsoft Sentinel through the API, by a Logic App
playbook, or manually from the Azure portal, aren't synchronized to the Defender
portal." The function used to PUT the incident (Direct). AlertBacked deploys a
scheduled analytics rule over SOCRadar_Identity_CL instead: the rule raises the
alert and the incident, which the Defender portal shows.

What is checked, all on the template text (the live run is in the report):

  * IncidentMode None | AlertBacked | Direct, default None; the legacy flag
    EnableCreateIncident means Direct only while IncidentMode is None.
  * The function PUTs (ENABLE_CREATE_INCIDENT) only in Direct.
  * The rules module deploys in EVERY mode and one switch expression turns the
    rule and the labeling automation rule on in AlertBacked only. ARM never
    deletes a resource whose condition went false, so a conditional module would
    leave the rule on after a switch back to None or Direct: two incidents per
    credential (the B2 defect found in the Incidents README review).
  * No credential column in the rule: the text "password" appears nowhere in the
    module (query, details, entities, descriptions).
  * The rule query keeps what was measured live: dedup on a SecurityAlert custom
    detail, a 12 minute hold, a 7 day rule window, at most 149 alerts a run, tolerance for a missing
    table or column, and every column that a detail or entity names is projected.
  * Alert name and description use at most 3 columns each (ARM rejected 5 in
    the Entra ID deployment: "The maximum allowed is 3").

Run: python3 tests/test_incident_mode.py
"""

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(os.path.dirname(HERE), "azuredeploy.json")

checks = 0
failures = []


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        failures.append(message)


doc = json.load(open(TEMPLATE, encoding="utf-8"))
params = doc["parameters"]
variables = doc["variables"]
resources = doc["resources"]


# --- a small ARM expression evaluator: only what these expressions use ------

class Expr:
    def __init__(self, text, scope):
        self.s = text
        self.i = 0
        self.scope = scope

    def ws(self):
        while self.i < len(self.s) and self.s[self.i] == " ":
            self.i += 1

    def parse(self):
        v = self.value()
        self.ws()
        assert self.i == len(self.s), "trailing text in %r" % self.s
        return v

    def value(self):
        self.ws()
        c = self.s[self.i]
        if c == "'":
            j = self.s.index("'", self.i + 1)
            v = self.s[self.i + 1:j]
            self.i = j + 1
            return v
        m = re.compile(r"[A-Za-z]+").match(self.s, self.i)
        name = m.group(0)
        self.i = m.end()
        self.ws()
        assert self.s[self.i] == "(", "expected ( after %s in %r" % (name, self.s)
        self.i += 1
        args = []
        self.ws()
        if self.s[self.i] != ")":
            while True:
                args.append(self.value())
                self.ws()
                if self.s[self.i] == ",":
                    self.i += 1
                    continue
                break
        assert self.s[self.i] == ")"
        self.i += 1
        v = self.call(name, args)
        while self.i < len(self.s) and self.s[self.i] == ".":
            m = re.compile(r"\.([A-Za-z]+)").match(self.s, self.i)
            v = v[m.group(1)]
            self.i = m.end()
        return v

    def call(self, name, a):
        sc = self.scope
        if name == "parameters":
            return sc["parameters"][a[0]]
        if name == "variables":
            return sc["variables"][a[0]]
        if name == "if":
            return a[1] if a[0] else a[2]
        if name == "and":
            return all(a)
        if name == "equals":
            return a[0] == a[1]
        if name == "empty":
            return a[0] in ("", None)
        if name == "string":
            return str(a[0])
        if name == "resourceGroup":
            return {"name": sc["deployment_rg"]}
        raise AssertionError("function %s is not supported by this test" % name)


def evaluate(text, scope):
    assert text.startswith("[") and text.endswith("]"), text
    return Expr(text[1:-1], scope).parse()


def scope_for(mode, legacy, workspace_rg=""):
    sc = {"parameters": {"IncidentMode": mode, "EnableCreateIncident": legacy,
                         "WorkspaceResourceGroup": workspace_rg},
          "variables": {}, "deployment_rg": "rg-deploy"}
    # variables may refer to each other; evaluate on demand in document order
    for k, v in variables.items():
        if isinstance(v, str) and v.startswith("[") and k in ("effectiveIncidentMode", "workspaceRg"):
            sc["variables"][k] = evaluate(v, sc)
    return sc


# --- parameters ------------------------------------------------------------

mode_param = params.get("IncidentMode")
check(mode_param is not None, "azuredeploy.json: parameter IncidentMode is gone")
if mode_param:
    check(mode_param.get("allowedValues") == ["None", "AlertBacked", "Direct"],
          "IncidentMode allowedValues are %r" % mode_param.get("allowedValues"))
    check(mode_param.get("defaultValue") == "None",
          "IncidentMode default is %r: the default must not change an existing install" %
          mode_param.get("defaultValue"))
check("Deprecated" in params["EnableCreateIncident"]["metadata"]["description"],
      "EnableCreateIncident must say it is deprecated in favour of IncidentMode")
check(params["EnableCreateIncident"].get("defaultValue") is False,
      "EnableCreateIncident default changed")

# --- the mode table --------------------------------------------------------

setting = None
for r in resources:
    if r["type"] == "Microsoft.Web/sites":
        for s in r["properties"]["siteConfig"]["appSettings"]:
            if s["name"] == "ENABLE_CREATE_INCIDENT":
                setting = s["value"]
check(setting is not None, "the Function App no longer has ENABLE_CREATE_INCIDENT")

module = next((r for r in resources if r.get("name") == "socradar-identity-alert-rules"), None)
check(module is not None, "azuredeploy.json: the alert rules module is gone")
rule_param = module["properties"]["parameters"]["RuleEnabled"]["value"] if module else None

for mode in ("None", "AlertBacked", "Direct"):
    for legacy in (False, True):
        sc = scope_for(mode, legacy)
        eff = sc["variables"]["effectiveIncidentMode"]
        want = "Direct" if (mode == "None" and legacy) else mode
        check(eff == want, "mode %s, legacy flag %s: effective mode is %s, expected %s"
              % (mode, legacy, eff, want))
        puts = evaluate(setting, sc).lower() == "true"
        check(puts == (want == "Direct"),
              "mode %s, legacy %s: ENABLE_CREATE_INCIDENT is %s, the function must PUT only in Direct"
              % (mode, legacy, puts))
        on = bool(evaluate(rule_param, sc))
        check(on == (want == "AlertBacked"),
              "mode %s, legacy %s: rule enabled is %s, it must be on only in AlertBacked"
              % (mode, legacy, on))

# --- the rules module ------------------------------------------------------

inner = module["properties"]["template"]
check("condition" not in module,
      "the rules module has a condition: ARM never deletes a resource whose condition went false, "
      "so a switch back from AlertBacked would leave the rule on (B2)")
check(module["properties"].get("expressionEvaluationOptions", {}).get("scope") == "inner",
      "the rules module must evaluate its expressions in its own scope")
sc = scope_for("None", False)
check(evaluate(module["resourceGroup"], sc) == "rg-deploy",
      "the rules module must default to the deployment resource group")
sc = scope_for("None", False, "rg-ws")
check(evaluate(module["resourceGroup"], sc) == "rg-ws",
      "the rules module ignores WorkspaceResourceGroup: cross-RG would put the rule in the wrong group")
deps = " ".join(module.get("dependsOn", []))
check("precheck-workspace-exists" in deps and "precheck-sentinel-onboarded" in deps,
      "the rules module must wait for both prechecks")

rule = next(r for r in inner["resources"] if r["type"].endswith("/alertRules"))
auto = next(r for r in inner["resources"] if r["type"].endswith("/automationRules"))
check(rule["properties"]["enabled"] == "[parameters('RuleEnabled')]",
      "the rule enabled expression is %r" % rule["properties"]["enabled"])
check(auto["properties"]["triggeringLogic"]["isEnabled"] == rule["properties"]["enabled"],
      "the labeling automation rule must use the same switch as the rule")
check(rule["kind"] == "Scheduled", "rule kind is %r" % rule["kind"])
check(rule["properties"]["incidentConfiguration"]["createIncident"] is True,
      "the rule must create the incident: that is the point of AlertBacked")
check(rule["properties"]["suppressionEnabled"] is False, "rule suppression must stay off")
check(rule["properties"]["queryFrequency"] == "PT1H",
      "queryFrequency is %r: Sentinel rejects a queryPeriod of 2 days or more with a frequency under "
      "1 hour (measured: \"When 'queryPeriod' greater than or equal to 2 days, the 'queryFrequency' "
      "should be greater than or equal to 1 hour\")" % rule["properties"]["queryFrequency"])
check(rule["properties"]["queryPeriod"] == "P7D",
      "queryPeriod is %r: the dedup against SecurityAlert only reaches as far back as the rule window, "
      "so with one day a row written again after 24 hours alerts again (Entra ID review B1)"
      % rule["properties"]["queryPeriod"])

labels = [l["labelName"] for l in auto["properties"]["actions"][0]["actionConfiguration"]["labels"]]
check(labels == ["SOCRadar", "IDENTITY", "LeakedCredential"],
      "labels are %r; Direct (sentinel.py) set SOCRadar, <source>.upper() = IDENTITY, LeakedCredential" % labels)

# --- no credential column anywhere in the module ----------------------------

module_text = json.dumps(inner).lower()
check("password" not in module_text,
      "the rules module mentions 'password': the rule must never read or project a credential column")
check("passw" not in module_text, "the rules module names a credential-looking column")

# --- the query ------------------------------------------------------------

q = rule["properties"]["query"]
check("SecurityAlert" in q and "DedupKey" in q and "leftanti" in q,
      "the query no longer drops rows that already have an alert (SecurityAlert anti-join on DedupKey)")
check("ago(7d)" in q and "ago(1d)" not in q,
      "the query window must match queryPeriod P7D")
check("ago(12m)" in q, "the 12 minute hold is gone: a late run could alert twice")
check(q.rstrip().endswith("| take 149"), "the query must end with take 149 (a rule raises at most 150 alerts)")
check('toupper(SocradarSeverity) == "LOW", "Low"' in q and '"Informational"' in q,
      "severity must follow what Direct sent: severity.capitalize(), Medium when there is none")
check("isfuzzy=true" in q, "isfuzzy is gone: the rule breaks where the table or SecurityAlert does not exist yet")
src_cols = re.findall(r'column_ifexists\("([a-z_]+)"', q)
check(src_cols, "no column_ifexists: the table is created by the first write")
check("ingestion_time()" not in q, "ingestion_time() cannot run on a union with a datatable")
for c in ("email_s", "record_id_s", "url_s", "monitored_domain_s", "entra_status_s", "severity_s"):
    check(c in src_cols, "source column %s is not read with column_ifexists" % c)
for c in src_cols:
    check(re.search(r"(_s|_b|_t|_d)$", c), "column %s lacks the Data Collector type suffix" % c)

project = re.findall(r"\| project (.*)", q)[-1]
projected = [x.strip() for x in project.split(",")]
named = set()
props = rule["properties"]
named.update(props["customDetails"].values())
for m in props["entityMappings"]:
    named.update(f["columnName"] for f in m["fieldMappings"])
named.add(props["alertDetailsOverride"]["alertSeverityColumnName"])
for fmt in ("alertDisplayNameFormat", "alertDescriptionFormat"):
    cols = re.findall(r"\{\{(\w+)\}\}", props["alertDetailsOverride"][fmt])
    check(len(set(cols)) <= 3, "%s uses %d columns, ARM allows 3" % (fmt, len(set(cols))))
    named.update(cols)
for c in sorted(named):
    check(c in projected, "column %s is named by the rule but not projected" % c)
check(props["customDetails"].get("DedupKey") == "DedupKey",
      "the DedupKey custom detail is gone: the next run cannot find the alert it already raised")
types = [m["entityType"] for m in props["entityMappings"]]
check(types == ["Account"],
      "entities are %r: Account only. A URL entity would let the Defender correlation engine merge "
      "unrelated credentials that share a login page" % types)

# --- the function identity gets no Sentinel role in AlertBacked --------------

SENTINEL_ROLES = ("3e150937-b8fe-4cfb-8069-0eaf05ecd056",  # Microsoft Sentinel Responder
                  "ab8e14d6-4a74-4a29-9ba8-549422addade",  # Microsoft Sentinel Contributor
                  "b24988ac-6180-42a0-ab88-20f7382dd24c")  # Contributor
for r in resources:
    if r["type"] == "Microsoft.Authorization/roleAssignments":
        rid = json.dumps(r["properties"]).lower()
        check(not any(x in rid for x in SENTINEL_ROLES),
              "a role assignment grants the Function App a Sentinel role: AlertBacked does not need one")

# --- literal strings that ARM would read as expressions ----------------------

allowed = {"[parameters('RuleEnabled')]"}


def walk(o):
    if isinstance(o, dict):
        for v in o.values():
            yield from walk(v)
    elif isinstance(o, list):
        for v in o:
            yield from walk(v)
    elif isinstance(o, str):
        yield o


for s in walk(inner):
    if s.startswith("[") and s.endswith("]") and not s.startswith("[["):
        ok = ("parameters(" in s or "variables(" in s or "resourceId(" in s or "concat(" in s or
              "guid(" in s) and s.count("(") == s.count(")")
        check(ok, "a string in the rules module reads as an ARM expression: %r" % s[:60])

if failures:
    print("")
    for f in failures:
        print("FAIL  " + f)
    print("\n%d of %d checks failed." % (len(failures), checks))
    sys.exit(1)
print("incident mode: None / AlertBacked / Direct, rules in every mode, no credential column (%d checks)" % checks)
