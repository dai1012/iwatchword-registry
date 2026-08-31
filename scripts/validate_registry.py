#!/usr/bin/env python3
"""
validate_registry.py — iwatchword-registry publication remediation validator (stdlib only)

Supports:
  - default / --root <dir>  local checkout validation
  - --base-url <url>        online recursive fetch validation

Checks:
  - All referenced paths exist / HTTP 200 + non-empty
  - JSON is object (dict) not array
  - manifest/index version >= 1
  - path not absolute, no "..", no backslash, no "//"
  - entry IDs non-empty unique and consistent with definition id
  - Provider: required camelCase fields, protocolFamily, https, host exactly api.deepseek.com,
             enabled/isDefault bool, supportedModelIds non-empty
  - Model: required fields, providerId exists and enabled, enabled model only references enabled provider
  - supportedModelIds <-> inventory bidirectional consistency
  - No recursive JSON key contains executable/script/command/shell/binary (case-insensitive)
  - DeepSeek (deepseek) and V4 (deepseek-v4-flash) must exist and enabled

Exit: 0 PASS, 1 FAIL with clear output.
"""
import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
import urllib.error

FORBIDDEN_SUBSTRINGS = ["executable", "script", "command", "shell", "binary"]
TRUSTED_HOST = "api.deepseek.com"
EXPECTED_PROVIDER_ID = "deepseek"
EXPECTED_MODEL_ID = "deepseek-v4-flash"

# Provider required camelCase fields
PROVIDER_REQUIRED_FIELDS = ["id", "displayName", "protocolFamily", "endpoint", "enabled", "isDefault", "supportedModelIds"]
PROVIDER_SNAKE_ALIASES = {
    "display_name": "displayName",
    "protocol_family": "protocolFamily",
    "supported_model_ids": "supportedModelIds",
    "is_default": "isDefault",
}
MODEL_REQUIRED_FIELDS = ["id", "providerId", "displayName", "enabled", "isDefault", "capabilities"]
MODEL_SNAKE_ALIASES = {
    "provider_id": "providerId",
    "display_name": "displayName",
    "is_default": "isDefault",
}

def is_valid_path(p: str):
    """Check path is relative, no absolute, no .., no backslash, no empty segment//.
    Handles percent-encoding blind spot: bounded repeated unquote to stable (anti double-encoding)
    and rejects any '%' residue in raw or decoded.
    """
    if not isinstance(p, str):
        return False, "path not string"
    trimmed = p.strip()
    if not trimmed:
        return False, "path empty"
    # Bounded repeated unquote to stable (defend double encoding like %252e%252e -> %2e%2e -> ..)
    decoded = trimmed
    for _ in range(5):
        nxt = urllib.parse.unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    # Reject any percent-encoding residue in raw or decoded
    if "%" in trimmed or "%" in decoded:
        return False, f"path must not contain percent-encoding: {p}"
    # After decoding, validate canonical form
    if decoded.startswith("/") or decoded.startswith("\\"):
        return False, f"path must not be absolute: {p}"
    if "\\" in decoded:
        return False, f"path must not contain backslash: {p}"
    # Empty segment / // check (split keeps empty strings)
    parts = decoded.split("/")
    if "" in parts:
        return False, f"path must not contain empty segment '//' or leading/trailing slash: {p}"
    if ".." in parts:
        return False, f"path must not contain '..': {p}"
    # Defensive: also reject any raw ".." substring that survived (covers edge)
    if ".." in decoded:
        # Only if it appears as segment, but we already checked; still block raw ".."
        # To avoid false positive on "...", we only block if ".." appears at all after decoding
        # Since valid paths never contain "..", safe to reject any occurrence
        return False, f"path must not contain '..': {p}"
    return True, ""

def contains_forbidden_key(obj, path_hint=""):
    """Recursively scan dict keys for forbidden substrings. Returns (found, key, hint)"""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                continue
            lk = k.lower()
            for forb in FORBIDDEN_SUBSTRINGS:
                if forb in lk:
                    return True, k, f"{path_hint}.{k}" if path_hint else k
            # recurse
            found, fk, hint = contains_forbidden_key(v, f"{path_hint}.{k}" if path_hint else k)
            if found:
                return True, fk, hint
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            found, fk, hint = contains_forbidden_key(item, f"{path_hint}[{idx}]")
            if found:
                return True, fk, hint
    return False, "", ""

def load_json_local(filepath):
    """Load local JSON file, checks existence, non-empty, JSON object, forbidden keys."""
    if not os.path.exists(filepath):
        return None, f"missing file: {filepath}"
    if not os.path.isfile(filepath):
        return None, f"not a file: {filepath}"
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        return None, f"cannot read {filepath}: {e}"
    if not data or len(data.strip()) == 0:
        return None, f"empty file: {filepath}"
    try:
        obj = json.loads(data.decode("utf-8"))
    except Exception as e:
        return None, f"invalid JSON {filepath}: {e}"
    if not isinstance(obj, dict):
        return None, f"JSON must be object (dict) in {filepath}, got {type(obj).__name__}"
    found, fk, hint = contains_forbidden_key(obj, filepath)
    if found:
        return None, f"forbidden key '{fk}' contains executable/script/command/shell/binary in {filepath} at {hint}"
    return obj, None

def fetch_json_online(url):
    """Fetch JSON via HTTP, checks 200, non-empty, JSON object, forbidden keys."""
    try:
        # Use Request with timeout
        req = urllib.request.Request(url, headers={"User-Agent": "iwatchword-registry-validator/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = getattr(resp, "status", resp.getcode())
            if status != 200:
                return None, f"HTTP {status} for {url}"
            data = resp.read()
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code} for {url}: {e.reason}"
    except urllib.error.URLError as e:
        return None, f"URL error for {url}: {e.reason}"
    except Exception as e:
        return None, f"fetch failed {url}: {e}"
    if not data or len(data.strip()) == 0:
        return None, f"empty response for {url}"
    try:
        obj = json.loads(data.decode("utf-8"))
    except Exception as e:
        return None, f"invalid JSON from {url}: {e}"
    if not isinstance(obj, dict):
        return None, f"JSON must be object (dict) from {url}, got {type(obj).__name__}"
    found, fk, hint = contains_forbidden_key(obj, url)
    if found:
        return None, f"forbidden key '{fk}' contains executable/script/command/shell/binary from {url} at {hint}"
    return obj, None

def validate_provider_definition(obj, filepath_hint):
    errors = []
    # Check required fields camelCase presence
    for field in PROVIDER_REQUIRED_FIELDS:
        if field not in obj:
            errors.append(f"{filepath_hint}: missing required field '{field}' (camelCase)")
    # Check snake_case aliases not present (would indicate wrong case)
    for snake, camel in PROVIDER_SNAKE_ALIASES.items():
        if snake in obj:
            errors.append(f"{filepath_hint}: forbidden snake_case key '{snake}' should be '{camel}'")
    # Also check case-insensitive but not exact camelCase? e.g., "DisplayName" vs "displayName"
    # If obj contains case-insensitive match but not exact, flag
    lower_map = {k.lower(): k for k in obj.keys()}
    for req in PROVIDER_REQUIRED_FIELDS:
        if req not in obj and req.lower() in lower_map:
            errors.append(f"{filepath_hint}: key case mismatch: found '{lower_map[req.lower()]}' expected '{req}'")

    # If missing critical fields, further checks limited
    # Validate id
    pid = obj.get("id")
    if not isinstance(pid, str) or not pid.strip():
        errors.append(f"{filepath_hint}: 'id' must be non-empty string")
    # displayName
    dn = obj.get("displayName")
    if not isinstance(dn, str) or not dn.strip():
        errors.append(f"{filepath_hint}: 'displayName' must be non-empty string")
    # protocolFamily
    pf = obj.get("protocolFamily")
    if pf != "openai-compatible":
        errors.append(f"{filepath_hint}: 'protocolFamily' must be 'openai-compatible', got {repr(pf)}")
    # endpoint
    endpoint = obj.get("endpoint")
    if not isinstance(endpoint, str) or not endpoint.strip():
        errors.append(f"{filepath_hint}: 'endpoint' must be non-empty string")
    else:
        ep = endpoint.strip()
        try:
            parsed = urllib.parse.urlparse(ep)
        except Exception as e:
            errors.append(f"{filepath_hint}: 'endpoint' URL parse failed: {e}")
            parsed = None
        if parsed is not None:
            if parsed.scheme.lower() != "https":
                errors.append(f"{filepath_hint}: 'endpoint' scheme must be https, got {repr(parsed.scheme)}")
            host = parsed.hostname or ""
            if host.lower() != TRUSTED_HOST:
                errors.append(f"{filepath_hint}: 'endpoint' host must be exactly {TRUSTED_HOST}, got {repr(host)}")
            if not host:
                errors.append(f"{filepath_hint}: 'endpoint' host missing")
            # userinfo check
            if parsed.username or parsed.password:
                errors.append(f"{filepath_hint}: 'endpoint' must not contain userinfo")
            # raw string host segment percent check (defense)
            # Extract raw host segment between "://" and next "/" or "?" or "#"
            raw = ep
            if "://" in raw:
                after = raw.split("://", 1)[1]
                host_seg = after.split("/")[0].split("?")[0].split("#")[0]
                # strip userinfo
                if "@" in host_seg:
                    host_seg = host_seg.split("@")[-1]
                # strip port
                if ":" in host_seg:
                    host_seg = host_seg.split(":")[0]
                if "%" in host_seg:
                    errors.append(f"{filepath_hint}: 'endpoint' host must not contain percent-encoding: {host_seg}")
                if host_seg.lower() != TRUSTED_HOST.lower():
                    # already checked via parsed.hostname, but raw check ensures no trick
                    pass
    # enabled
    enabled = obj.get("enabled")
    if not isinstance(enabled, bool):
        errors.append(f"{filepath_hint}: 'enabled' must be bool, got {type(enabled).__name__}: {repr(enabled)}")
    # isDefault
    is_default = obj.get("isDefault")
    if not isinstance(is_default, bool):
        errors.append(f"{filepath_hint}: 'isDefault' must be bool, got {type(is_default).__name__}: {repr(is_default)}")
    # supportedModelIds
    smids = obj.get("supportedModelIds")
    if not isinstance(smids, list) or len(smids) == 0:
        errors.append(f"{filepath_hint}: 'supportedModelIds' must be non-empty list")
    else:
        for idx, mid in enumerate(smids):
            if not isinstance(mid, str) or not mid.strip():
                errors.append(f"{filepath_hint}: 'supportedModelIds[{idx}]' must be non-empty string")
    # forbidden keys already checked globally, but just in case double
    return errors

def validate_model_definition(obj, filepath_hint, provider_by_id):
    errors = []
    for field in MODEL_REQUIRED_FIELDS:
        if field not in obj:
            errors.append(f"{filepath_hint}: missing required field '{field}'")
    for snake, camel in MODEL_SNAKE_ALIASES.items():
        if snake in obj:
            errors.append(f"{filepath_hint}: forbidden snake_case key '{snake}' should be '{camel}'")
    lower_map = {k.lower(): k for k in obj.keys()}
    for req in MODEL_REQUIRED_FIELDS:
        if req not in obj and req.lower() in lower_map:
            errors.append(f"{filepath_hint}: key case mismatch: found '{lower_map[req.lower()]}' expected '{req}'")

    mid = obj.get("id")
    if not isinstance(mid, str) or not mid.strip():
        errors.append(f"{filepath_hint}: 'id' must be non-empty string")
    pid = obj.get("providerId")
    if not isinstance(pid, str) or not pid.strip():
        errors.append(f"{filepath_hint}: 'providerId' must be non-empty string")
    else:
        # providerId must exist and enabled provider
        if provider_by_id is not None:
            prov = provider_by_id.get(pid.strip())
            if prov is None:
                errors.append(f"{filepath_hint}: 'providerId' {repr(pid)} does not exist in providers inventory")
            else:
                # provider exists, check enabled
                penabled = prov.get("enabled")
                # But provider_by_id stores raw obj dict
                if penabled is not True:
                    errors.append(f"{filepath_hint}: 'providerId' {repr(pid)} references disabled provider")
                # also enabled model only references enabled provider
                menabled = obj.get("enabled")
                if menabled is True and penabled is not True:
                    errors.append(f"{filepath_hint}: enabled model references disabled provider {repr(pid)}")
    dn = obj.get("displayName")
    if not isinstance(dn, str) or not dn.strip():
        errors.append(f"{filepath_hint}: 'displayName' must be non-empty string")
    enabled = obj.get("enabled")
    if not isinstance(enabled, bool):
        errors.append(f"{filepath_hint}: 'enabled' must be bool, got {type(enabled).__name__}: {repr(enabled)}")
    is_default = obj.get("isDefault")
    if not isinstance(is_default, bool):
        errors.append(f"{filepath_hint}: 'isDefault' must be bool, got {type(is_default).__name__}: {repr(is_default)}")
    caps = obj.get("capabilities")
    if not isinstance(caps, list):
        errors.append(f"{filepath_hint}: 'capabilities' must be list")
    else:
        for idx, c in enumerate(caps):
            if not isinstance(c, str):
                errors.append(f"{filepath_hint}: 'capabilities[{idx}]' must be string")
    return errors

def validate_local(root):
    errors = []
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        return [f"root not directory: {root}"], None

    def p(*parts):
        return os.path.join(root, *parts)

    # Load registry.json
    reg_path = p("registry.json")
    reg_obj, err = load_json_local(reg_path)
    if err:
        errors.append(err)
        return errors, None
    # Check version >=1
    ver = reg_obj.get("version")
    if not isinstance(ver, int) or ver < 1:
        # try allow Int but must be >=1
        if not isinstance(ver, int):
            # JSON may decode as int, but check
            try:
                iv = int(ver)
                if iv < 1:
                    errors.append(f"registry.json: version must be >=1, got {repr(ver)}")
            except:
                errors.append(f"registry.json: version must be integer >=1, got {repr(ver)}")
        else:
            errors.append(f"registry.json: version must be >=1, got {repr(ver)}")
    # Check registry.json is object already done
    # Check required index fields
    skills_index = reg_obj.get("skillsIndex")
    providers_index = reg_obj.get("providersIndex")
    models_index = reg_obj.get("modelsIndex")
    # skillsIndex must be retained and valid path
    if not isinstance(skills_index, str) or not skills_index.strip():
        errors.append("registry.json: missing or empty 'skillsIndex' (must retain skillsIndex)")
    else:
        ok, msg = is_valid_path(skills_index)
        if not ok:
            errors.append(f"registry.json: skillsIndex {msg}")
        else:
            # check file exists
            spath = p(skills_index)
            sobj, serr = load_json_local(spath)
            if serr:
                errors.append(serr)
            else:
                # validate skills index version >=1
                sver = sobj.get("version")
                if not isinstance(sver, int) or sver < 1:
                    errors.append(f"{skills_index}: version must be >=1, got {repr(sver)}")
                # validate skills entries
                skills = sobj.get("skills")
                if not isinstance(skills, list) or len(skills) == 0:
                    errors.append(f"{skills_index}: 'skills' must be non-empty list")
                else:
                    ids = []
                    for idx, entry in enumerate(skills):
                        if not isinstance(entry, dict):
                            errors.append(f"{skills_index}[{idx}]: entry must be object")
                            continue
                        eid = entry.get("id")
                        epath = entry.get("path")
                        if not isinstance(eid, str) or not eid.strip():
                            errors.append(f"{skills_index}[{idx}]: entry 'id' must be non-empty string")
                        else:
                            ids.append(eid.strip())
                        if not isinstance(epath, str) or not epath.strip():
                            errors.append(f"{skills_index}[{idx}]: entry 'path' must be non-empty string")
                        else:
                            okp, msgp = is_valid_path(epath)
                            if not okp:
                                errors.append(f"{skills_index}[{idx}]: path {msgp}")
                            else:
                                # check referenced skill file exists
                                fpath = p(epath)
                                fobj, ferr = load_json_local(fpath)
                                if ferr:
                                    errors.append(ferr)
                                else:
                                    # check skill id matches entry id? spec says entry id should match definition id?
                                    # For skills, we can check if definition has id field matching entry id if present
                                    did = fobj.get("id")
                                    if isinstance(did, str) and did.strip() != eid.strip():
                                        errors.append(f"{skills_index}[{idx}]: entry id {repr(eid)} != definition id {repr(did)}")
                                    # forbidden already checked
                    if len(ids) != len(set(ids)):
                        errors.append(f"{skills_index}: duplicate entry id found")
                    if "" in ids:
                        errors.append(f"{skills_index}: empty entry id")

    if not isinstance(providers_index, str) or not providers_index.strip():
        errors.append("registry.json: missing or empty 'providersIndex'")
    else:
        ok, msg = is_valid_path(providers_index)
        if not ok:
            errors.append(f"registry.json: providersIndex {msg}")

    if not isinstance(models_index, str) or not models_index.strip():
        errors.append("registry.json: missing or empty 'modelsIndex'")
    else:
        ok, msg = is_valid_path(models_index)
        if not ok:
            errors.append(f"registry.json: modelsIndex {msg}")

    # If providers/models index path invalid, cannot further check but continue
    providers_by_id = {}  # id -> raw provider obj
    providers_entries = {}  # id -> path
    models_by_id = {}
    models_entries = {}

    # Load providers index
    if isinstance(providers_index, str) and providers_index.strip():
        ok, msg = is_valid_path(providers_index)
        if ok:
            prov_idx_path = p(providers_index)
            prov_idx_obj, perr = load_json_local(prov_idx_path)
            if perr:
                errors.append(perr)
            else:
                pver = prov_idx_obj.get("version")
                if not isinstance(pver, int) or pver < 1:
                    errors.append(f"{providers_index}: version must be >=1, got {repr(pver)}")
                # providers key may be "providers" or fallback
                prov_list = None
                for key in ["providers", "entries", "items"]:
                    if key in prov_idx_obj and isinstance(prov_idx_obj[key], list):
                        prov_list = prov_idx_obj[key]
                        break
                if prov_list is None:
                    # try any list value?
                    # but strict
                    errors.append(f"{providers_index}: missing 'providers' list")
                    prov_list = []
                if not isinstance(prov_list, list) or len(prov_list) == 0:
                    errors.append(f"{providers_index}: 'providers' must be non-empty list")
                else:
                    seen_ids = set()
                    for idx, entry in enumerate(prov_list):
                        if not isinstance(entry, dict):
                            errors.append(f"{providers_index}[{idx}]: entry must be object")
                            continue
                        eid = entry.get("id")
                        epath = entry.get("path")
                        # also support fileURL/url aliases
                        if epath is None:
                            epath = entry.get("fileURL") or entry.get("url")
                        if not isinstance(eid, str) or not eid.strip():
                            errors.append(f"{providers_index}[{idx}]: entry 'id' must be non-empty string")
                            continue
                        eid_trim = eid.strip()
                        if eid_trim in seen_ids:
                            errors.append(f"{providers_index}[{idx}]: duplicate entry id {repr(eid_trim)}")
                        seen_ids.add(eid_trim)
                        if eid_trim in providers_entries:
                            errors.append(f"{providers_index}: duplicate provider id {repr(eid_trim)}")
                        if not isinstance(epath, str) or not epath.strip():
                            errors.append(f"{providers_index}[{idx}]: entry 'path' must be non-empty string")
                            continue
                        epath_trim = epath.strip()
                        okp, msgp = is_valid_path(epath_trim)
                        if not okp:
                            errors.append(f"{providers_index}[{idx}]: path {msgp}")
                            continue
                        providers_entries[eid_trim] = epath_trim
                    # Now load each provider definition
                    for pid, ppath in providers_entries.items():
                        fpath = p(ppath)
                        pobj, perr = load_json_local(fpath)
                        if perr:
                            errors.append(perr)
                            continue
                        # Check id consistency
                        did = pobj.get("id")
                        if not isinstance(did, str) or did.strip() != pid:
                            errors.append(f"{ppath}: entry id {repr(pid)} != definition id {repr(did)}")
                        # Validate provider fields
                        perrs = validate_provider_definition(pobj, ppath)
                        errors.extend(perrs)
                        # Deduplicate check for provider ids overall
                        if pid in providers_by_id:
                            errors.append(f"duplicate provider definition id {repr(pid)}")
                        providers_by_id[pid] = pobj
                # version already checked

    # Load models index similarly
    if isinstance(models_index, str) and models_index.strip():
        ok, msg = is_valid_path(models_index)
        if ok:
            mod_idx_path = p(models_index)
            mod_idx_obj, merr = load_json_local(mod_idx_path)
            if merr:
                errors.append(merr)
            else:
                mver = mod_idx_obj.get("version")
                if not isinstance(mver, int) or mver < 1:
                    errors.append(f"{models_index}: version must be >=1, got {repr(mver)}")
                mod_list = None
                for key in ["models", "entries", "items"]:
                    if key in mod_idx_obj and isinstance(mod_idx_obj[key], list):
                        mod_list = mod_idx_obj[key]
                        break
                if mod_list is None:
                    errors.append(f"{models_index}: missing 'models' list")
                    mod_list = []
                if not isinstance(mod_list, list) or len(mod_list) == 0:
                    errors.append(f"{models_index}: 'models' must be non-empty list")
                else:
                    seen_mids = set()
                    for idx, entry in enumerate(mod_list):
                        if not isinstance(entry, dict):
                            errors.append(f"{models_index}[{idx}]: entry must be object")
                            continue
                        eid = entry.get("id")
                        epath = entry.get("path")
                        if epath is None:
                            epath = entry.get("fileURL") or entry.get("url")
                        if not isinstance(eid, str) or not eid.strip():
                            errors.append(f"{models_index}[{idx}]: entry 'id' must be non-empty string")
                            continue
                        eid_trim = eid.strip()
                        if eid_trim in seen_mids:
                            errors.append(f"{models_index}[{idx}]: duplicate entry id {repr(eid_trim)}")
                        seen_mids.add(eid_trim)
                        if eid_trim in models_entries:
                            errors.append(f"{models_index}: duplicate model id {repr(eid_trim)}")
                        if not isinstance(epath, str) or not epath.strip():
                            errors.append(f"{models_index}[{idx}]: entry 'path' must be non-empty string")
                            continue
                        epath_trim = epath.strip()
                        okp, msgp = is_valid_path(epath_trim)
                        if not okp:
                            errors.append(f"{models_index}[{idx}]: path {msgp}")
                            continue
                        models_entries[eid_trim] = epath_trim
                    for mid, mpath in models_entries.items():
                        fpath = p(mpath)
                        mobj, merr = load_json_local(fpath)
                        if merr:
                            errors.append(merr)
                            continue
                        did = mobj.get("id")
                        if not isinstance(did, str) or did.strip() != mid:
                            errors.append(f"{mpath}: entry id {repr(mid)} != definition id {repr(did)}")
                        # Validate model, with provider_by_id available (may be incomplete if providers failed)
                        # Use current providers_by_id (maybe partial)
                        merrs = validate_model_definition(mobj, mpath, providers_by_id if providers_by_id else None)
                        errors.extend(merrs)
                        if mid in models_by_id:
                            errors.append(f"duplicate model definition id {repr(mid)}")
                        models_by_id[mid] = mobj

    # Post checks: bidirectional consistency
    if providers_by_id and models_by_id:
        # For each provider, supportedModelIds must be non-empty and each id must exist in models_by_id with providerId matching
        for pid, pobj in providers_by_id.items():
            smids = pobj.get("supportedModelIds") or []
            if not isinstance(smids, list):
                continue
            for smid in smids:
                if not isinstance(smid, str):
                    continue
                smid_trim = smid.strip()
                mobj = models_by_id.get(smid_trim)
                if mobj is None:
                    errors.append(f"provider {repr(pid)} supportedModelIds {repr(smid_trim)} not found in models inventory")
                else:
                    mpid = mobj.get("providerId")
                    if mpid != pid:
                        errors.append(f"model {repr(smid_trim)} providerId {repr(mpid)} does not match provider {repr(pid)} that lists it in supportedModelIds")
        # Each model must be listed in its provider's supportedModelIds
        for mid, mobj in models_by_id.items():
            mpid = mobj.get("providerId")
            if not isinstance(mpid, str):
                continue
            mpid_trim = mpid.strip()
            prov = providers_by_id.get(mpid_trim)
            if prov is None:
                # already flagged
                continue
            smids = prov.get("supportedModelIds") or []
            # check if mid in smids (trimmed compare)
            smids_trimmed = [s.strip() if isinstance(s, str) else s for s in smids]
            if mid not in smids_trimmed:
                errors.append(f"model {repr(mid)} with providerId {repr(mpid_trim)} not listed in provider's supportedModelIds {repr(smids)}")
        # Also check enabled model only references enabled provider already done in model validation, but re-check for completeness
        for mid, mobj in models_by_id.items():
            menabled = mobj.get("enabled")
            if menabled is True:
                prov = providers_by_id.get(mobj.get("providerId", "").strip())
                if prov is not None and prov.get("enabled") is not True:
                    errors.append(f"enabled model {repr(mid)} references disabled provider {repr(mobj.get('providerId'))}")

    # Check DeepSeek and V4 must exist and enabled
    if EXPECTED_PROVIDER_ID not in providers_by_id:
        errors.append(f"required provider {repr(EXPECTED_PROVIDER_ID)} not found in providers inventory")
    else:
        p = providers_by_id[EXPECTED_PROVIDER_ID]
        if p.get("enabled") is not True:
            errors.append(f"required provider {repr(EXPECTED_PROVIDER_ID)} must be enabled=true")
        if p.get("isDefault") is not True:
            errors.append(f"required provider {repr(EXPECTED_PROVIDER_ID)} must be isDefault=true")
        # also check displayName maybe? Task says DeepSeek Provider - we can warn if not DeepSeek
        # but not enforce strict beyond existence

    if EXPECTED_MODEL_ID not in models_by_id:
        errors.append(f"required model {repr(EXPECTED_MODEL_ID)} not found in models inventory")
    else:
        m = models_by_id[EXPECTED_MODEL_ID]
        if m.get("enabled") is not True:
            errors.append(f"required model {repr(EXPECTED_MODEL_ID)} must be enabled=true")
        if m.get("isDefault") is not True:
            errors.append(f"required model {repr(EXPECTED_MODEL_ID)} must be isDefault=true")
        if m.get("providerId") != EXPECTED_PROVIDER_ID:
            errors.append(f"required model {repr(EXPECTED_MODEL_ID)} must have providerId {repr(EXPECTED_PROVIDER_ID)}, got {repr(m.get('providerId'))}")

    # Also check registry.json retains skillsIndex already done, and providers/models index existence already checked
    # Ensure registry version is exactly 2? Task says v2, but we check >=1 already; we could enforce version 2
    if reg_obj is not None:
        if reg_obj.get("version") != 2:
            errors.append(f"registry.json: version must be 2 (got {repr(reg_obj.get('version'))}), expected 2 for remediation")
        # updatedAt check
        updated = reg_obj.get("updatedAt")
        if not isinstance(updated, str) or "2026-09-01" not in updated:
            errors.append(f"registry.json: updatedAt must contain 2026-09-01, got {repr(updated)}")

    return errors, {
        "providers_by_id": providers_by_id,
        "models_by_id": models_by_id,
        "providers_entries": providers_entries,
        "models_entries": models_entries,
    }

def validate_online(base_url):
    errors = []
    # Normalize base_url
    base_url = base_url.strip()
    if not base_url:
        return ["--base-url empty"], None
    # Determine registry URL
    if base_url.endswith(".json"):
        registry_url = base_url
        # base for resolving is directory of registry URL
        base_for_resolve = registry_url.rsplit("/", 1)[0] + "/"
    else:
        # ensure trailing slash for urljoin
        if not base_url.endswith("/"):
            base_for_resolve = base_url + "/"
        else:
            base_for_resolve = base_url
        registry_url = urllib.parse.urljoin(base_for_resolve, "registry.json")

    # Fetch registry.json
    reg_obj, err = fetch_json_online(registry_url)
    if err:
        errors.append(err)
        return errors, None
    ver = reg_obj.get("version")
    if not isinstance(ver, int) or ver < 1:
        try:
            iv = int(ver)
            if iv < 1:
                errors.append(f"registry.json: version must be >=1, got {repr(ver)}")
        except:
            errors.append(f"registry.json: version must be integer >=1, got {repr(ver)}")
    skills_index = reg_obj.get("skillsIndex")
    providers_index = reg_obj.get("providersIndex")
    models_index = reg_obj.get("modelsIndex")
    if not isinstance(skills_index, str) or not skills_index.strip():
        errors.append("registry.json: missing or empty 'skillsIndex'")
    else:
        ok, msg = is_valid_path(skills_index)
        if not ok:
            errors.append(f"registry.json: skillsIndex {msg}")
        else:
            skills_url = urllib.parse.urljoin(base_for_resolve, skills_index)
            sobj, serr = fetch_json_online(skills_url)
            if serr:
                errors.append(serr)
            else:
                sver = sobj.get("version")
                if not isinstance(sver, int) or sver < 1:
                    errors.append(f"{skills_index}: version must be >=1, got {repr(sver)}")
                skills = sobj.get("skills")
                if not isinstance(skills, list) or len(skills) == 0:
                    errors.append(f"{skills_index}: 'skills' must be non-empty list")
                else:
                    ids = []
                    for idx, entry in enumerate(skills):
                        if not isinstance(entry, dict):
                            errors.append(f"{skills_index}[{idx}]: entry must be object")
                            continue
                        eid = entry.get("id")
                        epath = entry.get("path")
                        if not isinstance(eid, str) or not eid.strip():
                            errors.append(f"{skills_index}[{idx}]: entry 'id' must be non-empty string")
                        else:
                            ids.append(eid.strip())
                        if not isinstance(epath, str) or not epath.strip():
                            errors.append(f"{skills_index}[{idx}]: entry 'path' must be non-empty string")
                        else:
                            okp, msgp = is_valid_path(epath)
                            if not okp:
                                errors.append(f"{skills_index}[{idx}]: path {msgp}")
                            else:
                                skill_url = urllib.parse.urljoin(base_for_resolve, epath)
                                fobj, ferr = fetch_json_online(skill_url)
                                if ferr:
                                    errors.append(ferr)
                                else:
                                    did = fobj.get("id")
                                    if isinstance(did, str) and did.strip() != eid.strip():
                                        errors.append(f"{skills_index}[{idx}]: entry id {repr(eid)} != definition id {repr(did)}")
                    if len(ids) != len(set(ids)):
                        errors.append(f"{skills_index}: duplicate entry id")
    if not isinstance(providers_index, str) or not providers_index.strip():
        errors.append("registry.json: missing or empty 'providersIndex'")
    else:
        ok, msg = is_valid_path(providers_index)
        if not ok:
            errors.append(f"registry.json: providersIndex {msg}")

    if not isinstance(models_index, str) or not models_index.strip():
        errors.append("registry.json: missing or empty 'modelsIndex'")
    else:
        ok, msg = is_valid_path(models_index)
        if not ok:
            errors.append(f"registry.json: modelsIndex {msg}")

    providers_by_id = {}
    providers_entries = {}
    models_by_id = {}
    models_entries = {}

    if isinstance(providers_index, str) and providers_index.strip():
        ok, msg = is_valid_path(providers_index)
        if ok:
            prov_idx_url = urllib.parse.urljoin(base_for_resolve, providers_index)
            prov_idx_obj, perr = fetch_json_online(prov_idx_url)
            if perr:
                errors.append(perr)
            else:
                pver = prov_idx_obj.get("version")
                if not isinstance(pver, int) or pver < 1:
                    errors.append(f"{providers_index}: version must be >=1, got {repr(pver)}")
                prov_list = None
                for key in ["providers", "entries", "items"]:
                    if key in prov_idx_obj and isinstance(prov_idx_obj[key], list):
                        prov_list = prov_idx_obj[key]
                        break
                if prov_list is None:
                    errors.append(f"{providers_index}: missing 'providers' list")
                    prov_list = []
                if not isinstance(prov_list, list) or len(prov_list) == 0:
                    errors.append(f"{providers_index}: 'providers' must be non-empty list")
                else:
                    seen = set()
                    for idx, entry in enumerate(prov_list):
                        if not isinstance(entry, dict):
                            errors.append(f"{providers_index}[{idx}]: entry must be object")
                            continue
                        eid = entry.get("id")
                        epath = entry.get("path") or entry.get("fileURL") or entry.get("url")
                        if not isinstance(eid, str) or not eid.strip():
                            errors.append(f"{providers_index}[{idx}]: entry 'id' must be non-empty string")
                            continue
                        eid_trim = eid.strip()
                        if eid_trim in seen:
                            errors.append(f"{providers_index}[{idx}]: duplicate entry id {repr(eid_trim)}")
                        seen.add(eid_trim)
                        if not isinstance(epath, str) or not epath.strip():
                            errors.append(f"{providers_index}[{idx}]: entry 'path' must be non-empty string")
                            continue
                        epath_trim = epath.strip()
                        okp, msgp = is_valid_path(epath_trim)
                        if not okp:
                            errors.append(f"{providers_index}[{idx}]: path {msgp}")
                            continue
                        providers_entries[eid_trim] = epath_trim
                    for pid, ppath in providers_entries.items():
                        prov_url = urllib.parse.urljoin(base_for_resolve, ppath)
                        pobj, perr = fetch_json_online(prov_url)
                        if perr:
                            errors.append(perr)
                            continue
                        did = pobj.get("id")
                        if not isinstance(did, str) or did.strip() != pid:
                            errors.append(f"{ppath}: entry id {repr(pid)} != definition id {repr(did)}")
                        perrs = validate_provider_definition(pobj, ppath)
                        errors.extend(perrs)
                        providers_by_id[pid] = pobj

    if isinstance(models_index, str) and models_index.strip():
        ok, msg = is_valid_path(models_index)
        if ok:
            mod_idx_url = urllib.parse.urljoin(base_for_resolve, models_index)
            mod_idx_obj, merr = fetch_json_online(mod_idx_url)
            if merr:
                errors.append(merr)
            else:
                mver = mod_idx_obj.get("version")
                if not isinstance(mver, int) or mver < 1:
                    errors.append(f"{models_index}: version must be >=1, got {repr(mver)}")
                mod_list = None
                for key in ["models", "entries", "items"]:
                    if key in mod_idx_obj and isinstance(mod_idx_obj[key], list):
                        mod_list = mod_idx_obj[key]
                        break
                if mod_list is None:
                    errors.append(f"{models_index}: missing 'models' list")
                    mod_list = []
                if not isinstance(mod_list, list) or len(mod_list) == 0:
                    errors.append(f"{models_index}: 'models' must be non-empty list")
                else:
                    seen = set()
                    for idx, entry in enumerate(mod_list):
                        if not isinstance(entry, dict):
                            errors.append(f"{models_index}[{idx}]: entry must be object")
                            continue
                        eid = entry.get("id")
                        epath = entry.get("path") or entry.get("fileURL") or entry.get("url")
                        if not isinstance(eid, str) or not eid.strip():
                            errors.append(f"{models_index}[{idx}]: entry 'id' must be non-empty string")
                            continue
                        eid_trim = eid.strip()
                        if eid_trim in seen:
                            errors.append(f"{models_index}[{idx}]: duplicate entry id {repr(eid_trim)}")
                        seen.add(eid_trim)
                        if not isinstance(epath, str) or not epath.strip():
                            errors.append(f"{models_index}[{idx}]: entry 'path' must be non-empty string")
                            continue
                        epath_trim = epath.strip()
                        okp, msgp = is_valid_path(epath_trim)
                        if not okp:
                            errors.append(f"{models_index}[{idx}]: path {msgp}")
                            continue
                        models_entries[eid_trim] = epath_trim
                    for mid, mpath in models_entries.items():
                        mod_url = urllib.parse.urljoin(base_for_resolve, mpath)
                        mobj, merr = fetch_json_online(mod_url)
                        if merr:
                            errors.append(merr)
                            continue
                        did = mobj.get("id")
                        if not isinstance(did, str) or did.strip() != mid:
                            errors.append(f"{mpath}: entry id {repr(mid)} != definition id {repr(did)}")
                        merrs = validate_model_definition(mobj, mpath, providers_by_id if providers_by_id else None)
                        errors.extend(merrs)
                        models_by_id[mid] = mobj

    # Bidirectional consistency
    if providers_by_id and models_by_id:
        for pid, pobj in providers_by_id.items():
            smids = pobj.get("supportedModelIds") or []
            if not isinstance(smids, list):
                continue
            for smid in smids:
                if not isinstance(smid, str):
                    continue
                smid_trim = smid.strip()
                mobj = models_by_id.get(smid_trim)
                if mobj is None:
                    errors.append(f"provider {repr(pid)} supportedModelIds {repr(smid_trim)} not found in models inventory")
                else:
                    mpid = mobj.get("providerId")
                    if mpid != pid:
                        errors.append(f"model {repr(smid_trim)} providerId {repr(mpid)} does not match provider {repr(pid)} that lists it in supportedModelIds")
        for mid, mobj in models_by_id.items():
            mpid = mobj.get("providerId")
            if not isinstance(mpid, str):
                continue
            mpid_trim = mpid.strip()
            prov = providers_by_id.get(mpid_trim)
            if prov is None:
                continue
            smids = prov.get("supportedModelIds") or []
            smids_trimmed = [s.strip() if isinstance(s, str) else s for s in smids]
            if mid not in smids_trimmed:
                errors.append(f"model {repr(mid)} with providerId {repr(mpid_trim)} not listed in provider's supportedModelIds {repr(smids)}")
        for mid, mobj in models_by_id.items():
            menabled = mobj.get("enabled")
            if menabled is True:
                prov = providers_by_id.get(mobj.get("providerId", "").strip())
                if prov is not None and prov.get("enabled") is not True:
                    errors.append(f"enabled model {repr(mid)} references disabled provider {repr(mobj.get('providerId'))}")

    if EXPECTED_PROVIDER_ID not in providers_by_id:
        errors.append(f"required provider {repr(EXPECTED_PROVIDER_ID)} not found in providers inventory")
    else:
        p = providers_by_id[EXPECTED_PROVIDER_ID]
        if p.get("enabled") is not True:
            errors.append(f"required provider {repr(EXPECTED_PROVIDER_ID)} must be enabled=true")
        if p.get("isDefault") is not True:
            errors.append(f"required provider {repr(EXPECTED_PROVIDER_ID)} must be isDefault=true")

    if EXPECTED_MODEL_ID not in models_by_id:
        errors.append(f"required model {repr(EXPECTED_MODEL_ID)} not found in models inventory")
    else:
        m = models_by_id[EXPECTED_MODEL_ID]
        if m.get("enabled") is not True:
            errors.append(f"required model {repr(EXPECTED_MODEL_ID)} must be enabled=true")
        if m.get("isDefault") is not True:
            errors.append(f"required model {repr(EXPECTED_MODEL_ID)} must be isDefault=true")
        if m.get("providerId") != EXPECTED_PROVIDER_ID:
            errors.append(f"required model {repr(EXPECTED_MODEL_ID)} must have providerId {repr(EXPECTED_PROVIDER_ID)}, got {repr(m.get('providerId'))}")

    if reg_obj is not None:
        if reg_obj.get("version") != 2:
            errors.append(f"registry.json: version must be 2 (got {repr(reg_obj.get('version'))}), expected 2 for remediation")
        updated = reg_obj.get("updatedAt")
        if not isinstance(updated, str) or "2026-09-01" not in updated:
            errors.append(f"registry.json: updatedAt must contain 2026-09-01, got {repr(updated)}")

    return errors, {
        "providers_by_id": providers_by_id,
        "models_by_id": models_by_id,
    }

def main():
    parser = argparse.ArgumentParser(description="Validate iwatchword-registry (local checkout or online fetch)")
    parser.add_argument("--root", type=str, default=".", help="Registry root directory (default: .)")
    parser.add_argument("--base-url", type=str, default=None, help="Base URL for online validation (e.g., https://raw.githubusercontent.com/dai1012/iwatchword-registry/main)")
    args = parser.parse_args()

    if args.base_url:
        print(f"[validate_registry] Mode: ONLINE --base-url {args.base_url}")
        errors, ctx = validate_online(args.base_url)
    else:
        print(f"[validate_registry] Mode: LOCAL --root {os.path.abspath(args.root)}")
        errors, ctx = validate_local(args.root)

    if errors:
        print("FAIL: registry validation failed")
        for e in errors:
            print(f"  - {e}")
        print(f"\nSummary: {len(errors)} error(s) found — FAIL")
        sys.exit(1)
    else:
        print("PASS: registry validation succeeded")
        # Print inventory summary for transparency
        if ctx:
            provs = ctx.get("providers_by_id") or {}
            mods = ctx.get("models_by_id") or {}
            print(f"  Providers: {len(provs)} ({', '.join(sorted(provs.keys()))})")
            print(f"  Models: {len(mods)} ({', '.join(sorted(mods.keys()))})")
        sys.exit(0)

if __name__ == "__main__":
    main()
