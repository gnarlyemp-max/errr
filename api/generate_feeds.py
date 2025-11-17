# api/generate_feeds.py
"""
Generates Hoyolab JSON feeds, uploads JSON to Supabase, converts each JSON to RSS (id-id),
and uploads the RSS back to Supabase under rss/<feed>-id.xml.

Channel metadata mapping:
 - genshin.json -> title "Genshin Impact ID - latest", link "https://genshin.hoyoverse.com/id/news", description "latest feed of Genshin Impact in id"
 - starrail.json -> title "Honkai Star Rail - Berita Hoyolab", link "https://hsr.hoyoverse.com/id-id/news", description "Berita terbaru Honkai Star Rail (ID)"

ENV:
- SUPABASE_URL
- SUPABASE_SERVICE_KEY (service_role)
- SUPABASE_BUCKET (default: feeds)
Optional fallback:
- GITHUB_TOKEN, GITHUB_REPO, etc.
"""
import os
import asyncio
import json
import base64
import traceback
import logging
import glob
import mimetypes
from urllib.parse import quote
from pathlib import Path
from datetime import datetime, timezone
from email.utils import format_datetime
from xml.sax.saxutils import escape

import requests
from hoyolabrssfeeds import FeedConfigLoader, GameFeedCollection
from dotenv import load_dotenv

load_dotenv()

# --- configuration ---
TMP_DIR = Path("/tmp/hoyolab_feeds")
TMP_CONFIG = TMP_DIR / "hoyolab-rss-feeds.toml"

# GitHub fallback (optional)
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = os.getenv("GITHUB_REPO")  # "owner/repo"
GITHUB_BRANCH = os.getenv("GITHUB_BRANCH", "main")
GITHUB_PREFIX = os.getenv("GITHUB_PREFIX", "").strip("/")
COMMITter_NAME = os.getenv("GITHUB_COMMIT_NAME", "hoyolab-bot")
COMMITter_EMAIL = os.getenv("GITHUB_COMMIT_EMAIL", "noreply@example.com")

# Supabase (preferred)
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET", "feeds")

# optional HOYOLAB_TOKEN if needed by generator
HOYOLAB_TOKEN = os.getenv("HOYOLAB_TOKEN")
# default language used for RSS channel; we'll force id-id
DEFAULT_LANGUAGE = os.getenv("FEED_LANGUAGE", "id-id")

# logging
logger = logging.getLogger("hoyolabrssfeeds_vercel")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)
logger.setLevel(logging.INFO)


def _ensure_tmp_config():
    TMP_DIR.mkdir(parents=True, exist_ok=True)
    if TMP_CONFIG.exists():
        logger.info("Using existing config at %s", TMP_CONFIG)
        return

    tmp_posix = str(TMP_DIR).replace("\\", "/")
    sample = f"""
language = "{DEFAULT_LANGUAGE}"
category_size = 10

[genshin]
feed.json.path = "{tmp_posix}/genshin.json"
feed.json.url = "https://example.org/genshin.json"
categories = ["Info", "Notices"]
title = "Genshin Impact News (auto)"

[starrail]
feed.json.path = "{tmp_posix}/starrail.json"
feed.json.url = "https://example.org/starrail.json"
categories = ["Info", "Notices"]
title = "Honkai: Starrail News (auto)"
"""
    TMP_CONFIG.write_text(sample, encoding="utf-8")
    logger.info("Wrote default config to %s", TMP_CONFIG)


async def generate_feeds():
    """Generate feeds according to config and return list of created file Paths."""
    if HOYOLAB_TOKEN:
        os.environ["HOYOLAB_TOKEN"] = HOYOLAB_TOKEN

    loader = FeedConfigLoader(TMP_CONFIG)
    all_configs = await loader.get_all_feed_configs()
    feed_collection = GameFeedCollection.from_configs(all_configs)
    await feed_collection.create_feeds()

    created = []
    for p in glob.glob(str(TMP_DIR / "*")):
        path = Path(p)
        if path.suffix in {".json", ".xml", ".rss"}:
            created.append(path)
    return created


# ---------- GitHub helpers (fallback) ----------
def _github_headers():
    if not GITHUB_TOKEN:
        raise RuntimeError("GITHUB_TOKEN not set")
    return {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}


def _repo_api_base():
    if not GITHUB_REPO or "/" not in GITHUB_REPO:
        raise RuntimeError("GITHUB_REPO must be set to 'owner/repo'")
    owner, repo = GITHUB_REPO.split("/", 1)
    return f"https://api.github.com/repos/{owner}/{repo}"


def _get_file_sha_if_exists(repo_base: str, path_in_repo: str):
    url = f"{repo_base}/contents/{path_in_repo}"
    params = {"ref": GITHUB_BRANCH}
    r = requests.get(url, headers=_github_headers(), params=params, timeout=15)
    if r.status_code == 200:
        return r.json().get("sha")
    if r.status_code == 404:
        return None
    r.raise_for_status()


def _put_file_to_github(repo_base: str, path_in_repo: str, content_bytes: bytes, message: str):
    b64 = base64.b64encode(content_bytes).decode("utf-8")
    sha = _get_file_sha_if_exists(repo_base, path_in_repo)
    payload = {
        "message": message,
        "content": b64,
        "branch": GITHUB_BRANCH,
        "committer": {"name": COMMITter_NAME, "email": COMMITter_EMAIL},
    }
    if sha:
        payload["sha"] = sha
    url = f"{repo_base}/contents/{path_in_repo}"
    r = requests.put(url, headers=_github_headers(), json=payload, timeout=30)
    if r.status_code in (200, 201):
        return r.json()
    else:
        raise RuntimeError(f"GitHub API error {r.status_code}: {r.text}")


def _build_repo_path(local_path: Path) -> str:
    parts = []
    if GITHUB_PREFIX:
        parts.append(GITHUB_PREFIX)
    parts.append(local_path.name)
    return "/".join(parts)


# ---------- Supabase helper (create-or-replace) ----------
def _put_file_to_supabase(local_path: Path, content_bytes: bytes, path_in_bucket: str):
    """
    Upload a file to Supabase Storage using the service role key.
    On Duplicate, delete existing object then retry.
    """
    if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
        raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_KEY must be set")

    safe_path = quote(path_in_bucket.strip("/"), safe="")
    upload_url = f"{SUPABASE_URL}/storage/v1/object/{SUPABASE_BUCKET}/{safe_path}"

    mimetype, _ = mimetypes.guess_type(path_in_bucket)
    if not mimetype:
        mimetype = "application/octet-stream"

    files = {"file": (os.path.basename(path_in_bucket), content_bytes, mimetype)}
    headers = {
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "apikey": SUPABASE_SERVICE_KEY,
        "User-Agent": "hoyolab-rss-feeds-uploader/1.0",
    }

    def _delete_object():
        delete_url = f"{SUPABASE_URL}/storage/v1/object/{SUPABASE_BUCKET}/{safe_path}"
        dh = {"Authorization": f"Bearer {SUPABASE_SERVICE_KEY}", "apikey": SUPABASE_SERVICE_KEY}
        dr = requests.delete(delete_url, headers=dh, timeout=15)
        # Supabase may return 200, 204 on success, 404 if missing
        if dr.status_code in (200, 204, 404):
            return dr
        raise RuntimeError(f"Supabase Storage DELETE error {dr.status_code}: {dr.text}")

    # Attempt to upload (create)
    r = requests.post(upload_url, headers=headers, files=files, timeout=30)

    if r.status_code in (200, 201):
        return r.json()

    # Duplicate handling
    if r.status_code in (400, 409) and "Duplicate" in r.text:
        logger.info("Object exists at %s — deleting and retrying upload", safe_path)
        _delete_object()
        r2 = requests.post(upload_url, headers=headers, files=files, timeout=30)
        if r2.status_code in (200, 201):
            return r2.json()
        raise RuntimeError(f"Supabase Storage API error after retry {r2.status_code}: {r2.text}")

    # Try PUT as a last-ditch upsert
    put_headers = headers.copy()
    put_headers["Content-Type"] = mimetypes.guess_type(path_in_bucket)[0] or "application/octet-stream"
    put_url = upload_url
    try:
        pr = requests.put(put_url, headers=put_headers, data=content_bytes, timeout=30)
        if pr.status_code in (200, 201):
            return pr.json() if pr.text else {}
    except Exception:
        pass

    raise RuntimeError(f"Supabase Storage API error {r.status_code}: {r.text}")


# ---------- JSON -> RSS conversion helpers ----------
def _iso_to_rfc822(iso_ts: str):
    if not iso_ts:
        return None
    try:
        dt = datetime.fromisoformat(iso_ts)
    except Exception:
        try:
            if iso_ts.endswith("Z"):
                dt = datetime.fromisoformat(iso_ts.rstrip("Z")).replace(tzinfo=timezone.utc)
            else:
                dt = datetime.fromisoformat(iso_ts)
        except Exception:
            dt = datetime.now(timezone.utc)
    return format_datetime(dt)


def _safe_cdata(s: str) -> str:
    if s is None:
        s = ""
    s = s.replace("]]>", "]]]]><![CDATA[>")
    return f"<![CDATA[{s}]]>"


def _build_rss_from_json(feed_json: dict, rss_self_url: str, language: str = "id-id",
                         channel_title: str = None, channel_link: str = None, channel_description: str = None) -> str:
    # force Indonesian feed language unless explicitly overridden
    lang = language or "id-id"
    title = channel_title or feed_json.get("title", "Untitled feed")
    link = channel_link or feed_json.get("home_page_url", feed_json.get("feed_url", ""))
    description = channel_description or feed_json.get("description", feed_json.get("summary", ""))

    items = feed_json.get("items", [])
    last_dates = [it["date_published"] for it in items if it.get("date_published")]
    last_build = _iso_to_rfc822(max(last_dates)) if last_dates else format_datetime(datetime.now(timezone.utc))

    header = '<?xml version="1.0" encoding="utf-8"?>\n'
    rss_open = '<rss xmlns:atom="http://www.w3.org/2005/Atom" xmlns:content="http://purl.org/rss/1.0/modules/content/" version="2.0">\n'
    channel_open = "  <channel>\n"
    channel_core = ""
    channel_core += f"    <title>{escape(title)}</title>\n"
    channel_core += f"    <link>{escape(link)}</link>\n"
    channel_core += f"    <description>{escape(description)}</description>\n"
    if rss_self_url:
        channel_core += f'    <atom:link href="{escape(rss_self_url)}" rel="self"/>\n'
    channel_core += "    <docs>http://www.rssboard.org/rss-specification</docs>\n"
    channel_core += "    <generator>hoyolab-json-to-rss</generator>\n"

    image_url = feed_json.get("image") or (items[0].get("image") if items else None)
    if image_url:
        channel_core += "    <image>\n"
        channel_core += f"      <url>{escape(image_url)}</url>\n"
        channel_core += f"      <title>{escape(title)}</title>\n"
        channel_core += f"      <link>{escape(link)}</link>\n"
        channel_core += "    </image>\n"

    channel_core += f"    <language>{escape(lang)}</language>\n"
    channel_core += f"    <lastBuildDate>{escape(last_build)}</lastBuildDate>\n"

    items_xml = ""
    for it in items:
        it_title = it.get("title") or ""
        it_link = it.get("url") or it.get("external_url") or ""
        it_desc = it.get("summary") or ""
        it_content = it.get("content_html") or it.get("content_text") or ""
        it_id = it.get("id") or it_link or it_title
        pub = _iso_to_rfc822(it.get("date_published")) if it.get("date_published") else None

        items_xml += "    <item>\n"
        items_xml += f"      <title>{escape(it_title)}</title>\n"
        if it_link:
            items_xml += f"      <link>{escape(it_link)}</link>\n"
        items_xml += f"      <description>{escape(it_desc)}</description>\n"
        if it_content:
            items_xml += f"      <content:encoded>{_safe_cdata(it_content)}</content:encoded>\n"
        is_permalink = isinstance(it_id, str) and (it_id.startswith("http://") or it_id.startswith("https://"))
        if is_permalink:
            items_xml += f'      <guid isPermaLink="true">{escape(it_id)}</guid>\n'
        else:
            items_xml += f'      <guid isPermaLink="false">{escape(str(it_id))}</guid>\n'
        if pub:
            items_xml += f"      <pubDate>{escape(pub)}</pubDate>\n"
        items_xml += "    </item>\n"

    channel_close = "  </channel>\n"
    rss_close = "</rss>\n"
    return header + rss_open + channel_open + channel_core + items_xml + channel_close + rss_close


def _convert_json_local_to_rss_bytes(local_json_path: Path, rss_self_url: str, language: str = "id-id",
                                     channel_title: str = None, channel_link: str = None, channel_description: str = None) -> bytes:
    data = json.loads(local_json_path.read_text(encoding="utf-8"))
    rss = _build_rss_from_json(data, rss_self_url=rss_self_url, language=language,
                               channel_title=channel_title, channel_link=channel_link, channel_description=channel_description)
    return rss.encode("utf-8")


# ---------- Main async wrapper ----------
async def main_async():
    _ensure_tmp_config()
    created = await generate_feeds()
    if not created:
        return {"ok": False, "message": "No feed files created", "files": []}

    results = []
    repo_base = None
    if GITHUB_REPO:
        try:
            repo_base = _repo_api_base()
        except Exception:
            repo_base = None

    # channel metadata map by stem
    CHANNEL_MAP = {
        "genshin": {
            "title": "Genshin Impact ID - latest",
            "link": "https://genshin.hoyoverse.com/id/news",
            "description": "latest feed of Genshin Impact in id",
            "language": "id-id",
        },
        "starrail": {
            "title": "Honkai Star Rail - Berita Hoyolab",
            "link": "https://hsr.hoyoverse.com/id-id/news",
            "description": "Berita terbaru Honkai Star Rail (ID)",
            "language": "id-id",
        },
    }

    for p in created:
        try:
            with p.open("rb") as fh:
                content = fh.read()

            logger.info("Local file %s size=%d bytes", p, len(content))

            # compute upload_path (like "genshin.json" or "starrail.json")
            repo_path = _build_repo_path(p)
            upload_path = repo_path.lstrip("/")

            # ensure upload_path doesn't accidentally include bucket prefix
            bucket_prefix = f"{SUPABASE_BUCKET}/"
            if upload_path.startswith(bucket_prefix):
                upload_path = upload_path[len(bucket_prefix):].lstrip("/")

            if not upload_path:
                upload_path = p.name

            upload_path = "/".join(part for part in upload_path.split("/") if part)

            # ---------- Upload JSON ----------
            json_public_url = None
            json_upload_resp = None
            if SUPABASE_URL and SUPABASE_SERVICE_KEY:
                try:
                    json_upload_resp = _put_file_to_supabase(p, content, upload_path)
                    json_public_url = f"{SUPABASE_URL}/storage/v1/object/public/{SUPABASE_BUCKET}/{quote(upload_path)}"
                    logger.info("Uploaded JSON to Supabase: %s", json_public_url)
                    results.append({"local": str(p), "json_repo_path": upload_path, "json_public_url": json_public_url, "json_api_response": json_upload_resp})
                except Exception as e:
                    tb = traceback.format_exc()
                    logger.exception("Failed uploading JSON %s", p)
                    results.append({"local": str(p), "error": str(e), "traceback": tb})
                    continue

            elif repo_base:
                try:
                    resp = _put_file_to_github(repo_base, repo_path, content, f"chore: update feed {p.name}")
                    raw_url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}/{repo_path}"
                    logger.info("Uploaded JSON to GitHub: %s", raw_url)
                    results.append({"local": str(p), "json_repo_path": repo_path, "json_raw_url": raw_url, "json_api_response": resp})
                    json_public_url = raw_url
                except Exception as e:
                    tb = traceback.format_exc()
                    logger.exception("Failed uploading JSON to GitHub for %s", p)
                    results.append({"local": str(p), "error": str(e), "traceback": tb})
                    continue
            else:
                logger.warning("No upload configured for %s; JSON remains local", p)
                results.append({"local": str(p), "json_local_path": str(p)})
                json_public_url = None

            # ---------- Convert JSON -> RSS and Upload RSS ----------
            try:
                # Decide channel metadata based on filename stem
                stem = p.stem.lower()
                meta = CHANNEL_MAP.get(stem, None)
                channel_title = meta["title"] if meta else None
                channel_link = meta["link"] if meta else None
                channel_description = meta["description"] if meta else None
                channel_language = meta["language"] if meta else DEFAULT_LANGUAGE

                # Name RSS file as "<stem>-id.xml"
                rss_name = f"{stem}-id.xml"
                rss_upload_path = f"rss/{rss_name}"
                # RSS public URL
                rss_public_url = f"{SUPABASE_URL}/storage/v1/object/public/{SUPABASE_BUCKET}/{quote(rss_upload_path)}" if SUPABASE_URL else None

                rss_bytes = _convert_json_local_to_rss_bytes(p, rss_self_url=rss_public_url, language=channel_language,
                                                             channel_title=channel_title, channel_link=channel_link, channel_description=channel_description)

                if SUPABASE_URL and SUPABASE_SERVICE_KEY:
                    rss_resp = _put_file_to_supabase(Path(rss_name), rss_bytes, rss_upload_path)
                    rss_public_url = f"{SUPABASE_URL}/storage/v1/object/public/{SUPABASE_BUCKET}/{quote(rss_upload_path)}"
                    logger.info("Uploaded RSS to Supabase: %s", rss_public_url)
                    results.append({"local": str(p), "rss_repo_path": rss_upload_path, "rss_public_url": rss_public_url, "rss_api_response": rss_resp})
                elif repo_base:
                    rss_repo_path = "/".join(part for part in [GITHUB_PREFIX, "rss", rss_name] if part)
                    resp = _put_file_to_github(repo_base, rss_repo_path, rss_bytes, f"chore: update rss {rss_name}")
                    raw_url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/{GITHUB_BRANCH}/{rss_repo_path}"
                    logger.info("Uploaded RSS to GitHub: %s", raw_url)
                    results.append({"local": str(p), "rss_repo_path": rss_repo_path, "rss_raw_url": raw_url, "rss_api_response": resp})
                else:
                    local_rss_path = p.parent / rss_name
                    local_rss_path.write_bytes(rss_bytes)
                    logger.info("Wrote RSS locally: %s", local_rss_path)
                    results.append({"local": str(p), "rss_local_path": str(local_rss_path)})
            except Exception as e:
                tb = traceback.format_exc()
                logger.exception("Failed to convert/upload RSS for %s", p)
                results.append({"local": str(p), "rss_error": str(e), "rss_traceback": tb})

        except Exception as e:
            tb = traceback.format_exc()
            logger.exception("Failed processing %s", p)
            results.append({"local": str(p), "error": str(e), "traceback": tb})

    return {"ok": True, "results": results}


# ---------- Vercel handler ----------
def handler(request):
    try:
        result = asyncio.run(main_async())
        return {"statusCode": 200, "headers": {"Content-Type": "application/json"}, "body": json.dumps(result)}
    except Exception as exc:
        tb = traceback.format_exc()
        logger.exception("Handler failure")
        body = json.dumps({"ok": False, "error": str(exc), "traceback": tb})
        return {"statusCode": 500, "headers": {"Content-Type": "application/json"}, "body": body}


# quick local debug
if __name__ == "__main__":
    print(json.dumps(asyncio.run(main_async()), indent=2))
