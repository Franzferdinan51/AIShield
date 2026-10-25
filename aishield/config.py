"""Model/server configuration — NOTHING about models is hardcoded in code.

Resolution order (highest wins): environment variables ->
config/models.local.yaml (untracked) -> config/models.yaml -> built-in
defaults (which name NO models: every role starts unset). The setup
wizard (`aishield setup`) writes the YAML.

  AISHIELD_LM_URL         model server base URL (any OpenAI-compatible
                          server: LM Studio, llama.cpp, Ollama, vLLM...)
  AISHIELD_TRIAGE_MODEL   model id for prose triage briefs (unset = auto-pick
                          the strongest loaded chat model)
  AISHIELD_DECISION_MODEL model id for typed decisions on the optional
                          decision endpoint (POST /v1/systemone-style:
                          {model, state, questions} -> calibrated answers).
                          Unset is fine: decisions then fall back to the
                          triage chat model, and finally to 'unsure'.
"""
import os

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_YAML = os.path.join(HERE, "config", "models.yaml")
MODELS_LOCAL_YAML = os.path.join(HERE, "config", "models.local.yaml")

DEFAULTS = {
    "server": {"url": "http://localhost:1234"},
    "roles": {
        "triage": {"model": None},
        "decision": {"model": None, "fallback": None, "protocol": "auto",
                     "endpoint": "/v1/systemone",
                     "decisions_endpoint": "/v1/decisions"},
    },
}


def load():
    cfg = {"server": dict(DEFAULTS["server"]),
           "roles": {k: dict(v) for k, v in DEFAULTS["roles"].items()}}
    try:
        import yaml
        for path in (MODELS_YAML, MODELS_LOCAL_YAML):
            if os.path.exists(path):
                with open(path) as f:
                    doc = yaml.safe_load(f) or {}
                if isinstance(doc.get("server"), dict):
                    cfg["server"].update(doc["server"])
                for role, vals in (doc.get("roles") or {}).items():
                    if isinstance(vals, dict) and role in cfg["roles"]:
                        cfg["roles"][role].update(vals)
    except Exception:
        pass
    if os.environ.get("AISHIELD_LM_URL"):
        cfg["server"]["url"] = os.environ["AISHIELD_LM_URL"]
    if os.environ.get("AISHIELD_API_KEY"):
        cfg["server"]["api_key"] = os.environ["AISHIELD_API_KEY"]
    if os.environ.get("AISHIELD_TRIAGE_MODEL"):
        cfg["roles"]["triage"]["model"] = os.environ["AISHIELD_TRIAGE_MODEL"]
    if os.environ.get("AISHIELD_DECISION_MODEL"):
        cfg["roles"]["decision"]["model"] = os.environ["AISHIELD_DECISION_MODEL"]
    cfg["server"]["url"] = str(cfg["server"]["url"]).rstrip("/")
    return cfg


def redacted(cfg):
    """Copy of a loaded config safe to display or hand to agents: a
    stored API key is masked to its last 4 characters."""
    import copy
    cfg = copy.deepcopy(cfg)
    key = (cfg.get("server") or {}).get("api_key")
    if key and not str(key).startswith("set ("):
        cfg["server"]["api_key"] = "set (…%s)" % str(key)[-4:]
    return cfg


def save(cfg):
    """Persist to the UNTRACKED local config — a wizard run may hold an
    API key or a private server address, neither belongs in version
    control. config.load() layers it above models.yaml."""
    import yaml
    os.makedirs(os.path.dirname(MODELS_LOCAL_YAML), exist_ok=True)
    tmp = MODELS_LOCAL_YAML + ".tmp"
    with open(tmp, "w") as f:
        yaml.safe_dump(cfg, f, sort_keys=False)
    os.replace(tmp, MODELS_LOCAL_YAML)  # atomic: never a half-written config
    return MODELS_LOCAL_YAML
