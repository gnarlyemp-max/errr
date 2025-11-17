#!/usr/bin/env python3
# supabase_json_to_rss.py
"""
Download a JSONFeed (or JSON produced by your generator) from a URL (e.g.
a Supabase public object URL), convert it into RSS 2.0 XML and optionally
upload the resulting XML to Supabase Storage.

Usage examples:
# convert remote JSON and save locally
python supabase_json_to_rss.py \
  --json-url "https://oclactzmovuugxjjossl.supabase.co/storage/v1/object/public/feeds/genshin.json" \
  --out-file "./genshin.xml"

# convert and upload to Supabase bucket (server-side; needs SUPABASE_SERVICE_KEY)
export SUPABASE_URL="https://oclactzmovuugxjjossl.supabase.co"
export SUPABASE_SERVICE_KEY="your_service_role_key"
export SUPABASE_BUCKET="feeds"
python supabase_json_to_rss.py \
  --json-url "https://oclactzmovuugxjjossl.supabase.co/storage/v1/object/public/feeds/genshin.json" \
  --upload-path "rss/genshin.xml"
"""

import argparse
import json
import os
import sys
import mimetypes
import traceback
from urllib.parse import quote, urlparse
from pathlib import Path
from datetime import datetime, timezone
from email.utils import format_datetime
from xml.sax.saxutils import escape

import requests

# ---------- helpers (conversion) ----------
def iso_to_rfc822(iso_ts: str):
    if not iso_ts:
        return None
    try:
        # Python 3.11 supports offset parsing
        dt = datetime.fromisoformat(iso_ts)
    except Exception:
        # fallback: try simple parse
        try:
            if iso_ts.endswith("Z"):
                dt = datetime.fromisoformat(iso_ts.rstrip("Z")).replace(tzinfo=timezone.utc)
            else:
                dt = datetime.fromisoformat(iso_ts)
        except Exception:
            dt = datetime.now(timezone.utc)
    return format_datetime(dt)

def safe_cdata(s: str) -> str:
    if s is None:
        s = ""
    s = s.replace(']]>', ']]]]><![CDATA[>')
    return f"<![CDATA[{s}]]>"

def build_rss_from_json(feed_json: dict, self_url: str = None, language: str = None,
                        channel_title: str = None, channel_link: str = None, channel_description: str = None) -> str:
    title = channel_title or feed_json.get("title", "Untitled feed")
    link = channel_link or feed_json.get("home_page_url", feed_json.get("feed_url", ""))
    description = channel_description or feed_json.get("description", feed_json.get("summary", ""))
    lang = language or feed_json.get("language", "")

    items = feed_json.get("items", [])

    last_dates = []
    for it in items:
        if it.get("date_published"):
            last_dates.append(it["date_published"])
    last_build = iso_to_rfc822(max(last_dates)) if last_dates else format_datetime(datetime.now(timezone.utc))

    header = '<?xml version="1.0" encoding="utf-8"?>\n'
    rss_open = '<rss xmlns:atom="http://www.w3.org/2005/Atom" xmlns:content="http://purl.org/rss/1.0/modules/content/" version="2.0">\n'
    channel_open = "  <channel>\n"
    channel_core = ""
    channel_core += f"    <title>{escape(title)}</title>\n"
    channel_core += f"    <link>{escape(link)}</link>\n"
    channel_core += f"    <description>{escape(description)}</description>\n"
    if self_url:
        channel_core += f'    <atom:link href="{escape(self_url)}" rel="self"/>\n'
    channel_core += "    <docs>http://www.rssboard.org/rss-specification</docs>\n"
    channel_core += "    <generator>supabase-json-to-rss</generator>\n"

    image_url = feed_json.get("image") or (items[0].get("image") if items else None)
    if image_url:
        channel_core += "    <image>\n"
        channel_core += f"      <url>{escape(image_url)}</url>\n"
        channel_core += f"      <title>{escape(title)}</title>\n"
        channel_core += f"      <link>{escape(link)}</link>\n"
        channel_core += "    </image>\n"

    if lang:
        channel_core += f"    <language>{escape(lang)}</language>\n"
    channel_core += f"    <lastBuildDate>{escape(last_build)}</lastBuildDate>\n"

    items_xml = ""
    for it in items:
        it_title = it.get("title") or ""
        it_link = it.get("url") or it.get("external_url") or ""
        it_desc = it.get("summary") or ""
        it_content = it.get("content_html") or it.get("content_text") or ""
        it_id = it.get("id") or it_link or it_title
        pub = iso_to_rfc822(it.get("date_published")) if it.get("date_published") else None

        items_xml += "    <item>\n"
        items_xml += f"      <title>{escape(it_title)}</title>\n"
        if it_link:
            items_xml += f"      <link>{escape(it_link)}</link>\n"
        items_xml += f"      <description>{escape(it_desc)}</description>\n"
        if it_content:
            items_xml += f"      <content:encoded>{safe_cdata(it_content)}</content:encoded>\n"
        is_permalink = False
        try:
            is_permalink = isinstance(it_id, str) and (it_id.startswith("http://") or it_id.startswith("https://"))
        except Exception:
            is_permalink = False
        if is_permalink:
            items_xml += f"      <guid isPermaLink=\"true\">{escape(it_id)}</guid>\n"
        else:
            items_xml += f'      <guid isPermaLink="false">{escape(str(it_id))}</guid>\n'
        if pub:
            items_xml += f"      <pubDate>{escape(pub)}</pubDate>\n"
        items_xml += "    </item>\n"

    channel_close = "  </channel>\n"
    rss_close = "</rss>\n"
    return header + rss_open + channel_open + channel_core + items_xml + channel_close + rss_close

# ---------- Supabase upload helper ----------
def upload_to_supabase(supabase_url: str, service_key: str, bucket: str, path_in_bucket: str, content_bytes: bytes):
    if not supabase_url or not service_key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_KEY are required for upload")
    safe_path = quote(path_in_bucket.strip("/"), safe="")
    upload_url = f"{supabase_url.rstrip('/')}/storage/v1/object/{bucket}/{safe_path}"
    headers = {
        "Authorization": f"Bearer {service_key}",
        "apikey": service_key,
        "User-Agent": "supabase-json-to-rss/1.0",
    }
    files = {"file": (os.path.basename(path_in_bucket), content_bytes, mimetypes.guess_type(path_in_bucket)[0] or "application/xml")}
    r = requests.post(upload_url, headers=headers, files=files, timeout=30)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Supabase Storage API error {r.status_code}: {r.text}")
    return r.json()

# ---------- main ----------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--json-url", help="URL of JSON feed (public)", required=True)
    p.add_argument("--out-file", help="Local output XML file (optional). If omitted, a temp name is used", default=None)
    p.add_argument("--self-url", help="atom:self URL to include in channel (optional)", default=None)
    p.add_argument("--language", help="channel language override (e.g. id)", default=None)
    p.add_argument("--title", help="channel title override", default=None)
    p.add_argument("--link", help="channel link override", default=None)
    p.add_argument("--description", help="channel description override", default=None)
    p.add_argument("--upload-path", help="If set, upload the RSS to Supabase at this path (e.g. 'rss/genshin.xml')", default=None)
    args = p.parse_args()

    # Get JSON
    try:
        r = requests.get(args.json_url, timeout=30)
        r.raise_for_status()
    except Exception as e:
        print("Failed to fetch JSON:", e, file=sys.stderr)
        sys.exit(2)

    try:
        feed_json = r.json()
    except Exception as e:
        print("Invalid JSON from URL:", e, file=sys.stderr)
        sys.exit(2)

    rss_xml = build_rss_from_json(feed_json, self_url=args.self_url, language=args.language,
                                  channel_title=args.title, channel_link=args.link, channel_description=args.description)

    # determine output path
    out_path = Path(args.out_file) if args.out_file else Path.cwd() / (Path(urlparse(args.json_url).path).stem + ".xml")
    out_path.write_text(rss_xml, encoding="utf-8")
    print("Wrote RSS to", out_path)

    if args.upload_path:
        SUPABASE_URL = os.getenv("SUPABASE_URL", "")
        SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
        SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET", "feeds")
        if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
            print("SUPABASE_URL and SUPABASE_SERVICE_KEY must be set in environment to upload", file=sys.stderr)
            sys.exit(3)
        try:
            resp = upload_to_supabase(SUPABASE_URL, SUPABASE_SERVICE_KEY, SUPABASE_BUCKET, args.upload_path, out_path.read_bytes())
            public_url = f"{SUPABASE_URL.rstrip('/')}/storage/v1/object/public/{SUPABASE_BUCKET}/{quote(args.upload_path)}"
            print("Uploaded to Supabase. public URL:", public_url)
            print("Supabase response:", resp)
        except Exception as e:
            print("Upload failed:", e, file=sys.stderr)
            traceback.print_exc()
            sys.exit(4)


if __name__ == "__main__":
    main()
