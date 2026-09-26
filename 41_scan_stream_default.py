#!/usr/bin/python3

import os
import sys
import time
import socket
import re
import logging
from pathlib import Path
from urllib.parse import urlparse
from multiprocessing import Pool

import cv2
import requests
import pymysql

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import substream
except ImportError:
    substream = None

if hasattr(os, "geteuid") and os.geteuid() == 0:
    print("Execution as root is prohibited", file=sys.stderr)

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("RTSP_Scanner")

DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
DB_PORT = int(os.environ.get("DB_PORT", 3306))
DB_USER = os.environ.get("DB_USER", "rtsp_service_user")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
DB_NAME = os.environ.get("DB_NAME", "video_surveillance")

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

host_ip = socket.gethostbyname(socket.gethostname())
STORAGE_DIR = Path(os.environ.get("STORAGE_DIR", "/var/www/html/scan")).resolve()
WEB_BASE_URL = os.environ.get("WEB_BASE_URL", f"http://{host_ip}/scan")

STORAGE_DIR.mkdir(parents=True, exist_ok=True, mode=0o755)


def get_connection():
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        autocommit=False
    )


def sanitize_filename(raw_name: str) -> str:
    base = os.path.basename(str(raw_name))
    clean = re.sub(r'[^a-zA-Z0-9_\-]', '_', base)
    return clean or "unknown_stream"


def is_valid_rtsp_url(url: str) -> bool:
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url.strip())
        if parsed.scheme.lower() not in ("rtsp", "rtsps"):
            return False
        if not parsed.hostname or parsed.hostname.lower() in ("localhost", "127.0.0.1", "::1"):
            return False
        return True
    except Exception:
        return False


def select_ip_list():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            query = """
                SELECT `ip`, 
                       CONCAT(REPLACE(`ip`, '.', '_'), '-', `country_code`, '-', `region`, '-', `city`) AS 'name_camera'
                FROM `rtsp_scan` 
                WHERE `url` IS NULL AND `up` = %s;
            """
            cursor.execute(query, (os.uname(),))
            return cursor.fetchall()
    finally:
        conn.close()


def insert_url(link_one, ip, link, login, passwd):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            query = """
                UPDATE `rtsp_scan` 
                SET `url` = %s, 
                    `up` = %s, 
                    `link` = %s, 
                    `login` = %s, 
                    `passwd` = %s
                WHERE `ip` = %s;
            """
            logger.info("Updating scan result for IP: %s (login: %s)", ip, login)
            cursor.execute(query, (link_one, os.uname(), link, login, passwd, ip))
        conn.commit()
    except Exception as err:
        conn.rollback()
        logger.error("Database error for IP %s: %s", ip, err)
    finally:
        conn.close()


def job(ip_data):
    stream_url = ip_data[0]
    cam_ip = ip_data
    raw_name = ip_data
    login = ip_data
    passwd = ip_data

    if not is_valid_rtsp_url(stream_url):
        logger.warning("Invalid stream URL: %s", stream_url)
        return

    cap = None
    try:
        cap = cv2.VideoCapture(stream_url)
        ret, frame = cap.read()
        if ret and frame is not None:
            safe_name = sanitize_filename(raw_name)
            target_file = (STORAGE_DIR / f"{safe_name}.jpg").resolve()

            if not str(target_file).startswith(str(STORAGE_DIR)):
                logger.error("Path traversal detected: %s", raw_name)
                return

            cv2.imwrite(str(target_file), frame)
            url_link = f"{WEB_BASE_URL}/{safe_name}.jpg"
            insert_url(stream_url, cam_ip, url_link, login, passwd)
    except Exception as e:
        logger.debug("Frame capture failed for %s: %s", stream_url, e)
    finally:
        if cap is not None:
            cap.release()


def main():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT `path`, `login`, `passwd` FROM `view_support_path_default`")
            link_list = cursor.fetchall()
    finally:
        conn.close()

    for link in link_list:
        ip_records = select_ip_list()
        rtsp_list = []
        for rec in ip_records:
            stream_candidate = link[0].replace('ip_for_replace', rec[0])
            rtsp_list.append([stream_candidate, rec[0], rec, link, link])

        start = time.time()
        with Pool(processes=min(50, len(rtsp_list) or 1)) as p:
            p.map(job, rtsp_list)

        end = time.time()
        sl_tm = 300 - int((end - start))
        logger.info("Batch completed. Sleep: %d seconds", sl_tm)
        if sl_tm > 0:
            time.sleep(sl_tm)


if __name__ == "__main__":
    start_time = time.time()
    main()
    done = time.time() - start_time

    if TOKEN and CHAT_ID:
        send_url = f'https://api.telegram.org/bot{TOKEN}/sendMessage'
        try:
            requests.post(send_url, json={
                'chat_id': CHAT_ID,
                'text': f"41_scan_stream_default done in {int(done)}s"
            }, timeout=10)
        except Exception as e:
            logger.error("Telegram notification failed: %s", e)

    if substream:
        substream.main()