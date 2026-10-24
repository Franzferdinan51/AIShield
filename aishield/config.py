"""Model/server configuration — NOTHING about models is hardcoded in code.

Resolution order (highest wins): environment variables -> config/models.yaml
-> built-in defaults. The setup wizard (`aishield setup`) writes the YAML.

  AISHIELD_LM_URL        model server base URL (LM Studio or any
                         OpenAI-compatible server)
  AISHIELD_TRIAGE_MODEL   model id for prose triage briefs (unset = auto-pick
                         the strongest loaded chat model)
  AISHIELD_DECISION_MODEL model id for typed decisions (SystemOne wire,
                         POST /v1/systemone); any decision-model family works
                         as long as the server exposes that endpoint
"""
import os

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_YAML = os.path.join(HERE, "config", "models.yaml")

DEFAULTS = {
    "server": {"url": "http://localhost:1234"},
    "roles": {
        "triage": {"model": None},
        "decision": {"model": "d1-3b", "fallback": "d1-omni-600m",
                     "endpoint": "/v1/systemone"},
    },
}


def load():
    cfg = {"server": dict(DEFAULTS["server"]),
           "roles": {k: dict(v) for k, v in DEFAULTS["roles"].items()}}
    try:
        import yaml
        if os.path.exists(MODELS_YAML):
            with open(MODELS_YAML) as f:
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
    if os.environ.get("AISHIELD_TRIAGE_MODEL"):
        cfg["roles"]["triage"]["model"] = os.environ["AISHIELD_TRIAGE_MODEL"]
    if os.environ.get("AISHIELD_DECISION_MODEL"):
        cfg["roles"]["decision"]["model"] = os.environ["AISHIELD_DECISION_MODEL"]
    cfg["server"]["url"] = str(cfg["server"]["url"]).rstrip("/")
    return cfg


def save(cfg):
    import yaml
    os.makedirs(os.path.dirname(MODELS_YAML), exist_ok=True)
    with open(MODELS_YAML, "w") as f:
        yaml.safe_dump(cfg, f, sort_keys=False)
    return MODELS_YAML
