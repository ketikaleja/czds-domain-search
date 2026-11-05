#!/usr/bin/env python3
'''
Download ICANN CZDS zone files and search them for domains containing a keyword.

Usage:
    # 1. Download zone files (all approved TLDs, or just some)
    python domain_scraper.py download
    python domain_scraper.py download --tlds com net org

    # 2. Search downloaded zones and export matches to Excel
    python domain_scraper.py search bitcoin
    python domain_scraper.py search bitcoin crypto --tlds com net --mode prefix -o crypto.xlsx

Credentials are read from CZDS_USER / CZDS_PASS environment variables, or prompted for.
'''

import argparse
import asyncio
import getpass
import gzip
import logging
import os
import re
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime

ZONES_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'zones')
CHUNK_SIZE = 16 * 1024 * 1024  # Decompressed bytes read per chunk while searching
EXCEL_MAX_ROWS = 1_048_575     # Excel row limit minus the header row
MAX_AGE_HOURS  = 25           # Zone files refresh daily; skip re-downloading newer files

log = logging.getLogger('domain_scraper')


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def tld_from_url(url: str) -> str:
    '''https://czds-api.icann.org/czds/downloads/com.zone -> com'''
    return url.rstrip('/').split('/')[-1].split('.')[0].lower()


async def download_one(client, url: str, semaphore: asyncio.Semaphore, force: bool) -> tuple:
    '''Download a single zone file, keeping it gzip-compressed. Returns (tld, status).'''
    tld  = tld_from_url(url)
    dest = os.path.join(ZONES_DIR, f'{tld}.txt.gz')

    if not force and os.path.exists(dest) and (time.time() - os.path.getmtime(dest)) < MAX_AGE_HOURS * 3600:
        return tld, 'skipped (fresh)'

    async with semaphore:
        part = dest + '.part'
        for attempt in range(1, 4):
            try:
                async with client.session.get(url, headers=client.headers) as response:
                    with open(part, 'wb') as f:
                        async for chunk in response.content.iter_chunked(1024 * 1024):
                            f.write(chunk)
                os.replace(part, dest)
                size_mb = os.path.getsize(dest) / 1024 / 1024
                log.info(f'Downloaded {tld} ({size_mb:,.1f} MB)')
                return tld, 'ok'
            except Exception as e:
                status = getattr(e, 'status', None)
                if os.path.exists(part):
                    os.remove(part)
                # 401/403/404 mean no access (expired/revoked) - retrying will not help
                if status in (401, 403, 404) or attempt == 3:
                    log.warning(f'Failed {tld}: {e}')
                    return tld, f'failed: {status or e}'
                log.warning(f'Retrying {tld} (attempt {attempt}) after error: {e}')
                await asyncio.sleep(5 * attempt)


async def list_zones(username: str, password: str):
    from czds import CZDS

    async with CZDS(username, password) as client:
        tlds = sorted(tld_from_url(u) for u in await client.fetch_zone_links())

    print(f'\nYou have access to {len(tlds):,} zones:\n')
    print(', '.join(tlds))


async def download_zones(username: str, password: str, tlds: list, concurrency: int, force: bool):
    from czds import CZDS

    import aiohttp

    os.makedirs(ZONES_DIR, exist_ok=True)

    client = CZDS(username, password)
    try:
        try:
            await client.authenticate()
        except aiohttp.ClientResponseError as e:
            if e.status == 401:
                sys.exit('Login failed (401): ICANN rejected the username/password. '
                         'Check them at https://czds.icann.org and unset CZDS_USER/CZDS_PASS if they are wrong.')
            raise

        links = sorted(await client.fetch_zone_links())

        if tlds:
            wanted = {t.lower().lstrip('.') for t in tlds}
            links  = [u for u in links if tld_from_url(u) in wanted]
            missing = wanted - {tld_from_url(u) for u in links}
            if missing:
                log.warning(f'No access to: {", ".join(sorted(missing))}')

        log.info(f'Downloading {len(links):,} zone file(s) to {ZONES_DIR}')
        semaphore = asyncio.Semaphore(concurrency)
        results   = await asyncio.gather(*(download_one(client, u, semaphore, force) for u in links))
    finally:
        await client.close()

    counts = Counter(status.split(':')[0] for _, status in results)
    log.info(f'Done: {dict(counts)}')
    failed = [tld for tld, status in results if status.startswith('failed')]
    if failed:
        log.info(f'Failed TLDs: {", ".join(failed)}')


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

def build_pattern(keywords: list, mode: str, tld: str) -> re.Pattern:
    '''
    Regex that matches the owner name at the start of a zone file line, e.g.
        "example.com.\t172800\tin\tns\tns1.example.com."
    Only second-level names directly under the TLD are matched, so glue records
    (ns1.example.com) and nameserver values are ignored.
    '''
    kw    = b'|'.join(re.escape(k.lower().encode()) for k in keywords)
    label = rb'[a-z0-9_-]*'
    body  = {
        'contains': label + rb'(?:' + kw + rb')' + label,
        'prefix':   rb'(?:' + kw + rb')' + label,
        'suffix':   label + rb'(?:' + kw + rb')',
        'exact':    rb'(?:' + kw + rb')',
    }[mode]
    return re.compile(rb'^(' + body + rb')\.' + re.escape(tld.encode()) + rb'\.\s', re.MULTILINE | re.IGNORECASE)


def search_zone(path: str, keywords: list, mode: str) -> tuple:
    '''Stream through one gzip zone file. Returns (tld, sorted list of matching labels).'''
    tld     = os.path.basename(path).split('.')[0]
    pattern = build_pattern(keywords, mode, tld)
    found   = set()
    tail    = b''

    with gzip.open(path, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            data = tail + chunk
            cut  = data.rfind(b'\n') + 1      # Only scan complete lines; carry the rest over
            tail = data[cut:]
            found.update(m.lower() for m in pattern.findall(data, 0, cut))
        if tail:
            found.update(m.lower() for m in pattern.findall(tail + b'\n'))

    return tld, sorted(label.decode() for label in found)


def matched_keyword(label: str, keywords: list) -> str:
    return ', '.join(k for k in keywords if k in label)


def write_excel(path: str, results: dict, keywords: list, mode: str, enriched: dict = None):
    from openpyxl import Workbook
    from openpyxl.utils import get_column_letter

    from domain_enrich import COLUMNS as ENRICH_COLUMNS

    wb    = Workbook(write_only=True)
    total = sum(len(v) for v in results.values())

    # Summary sheet
    ws = wb.create_sheet('Summary')
    ws.append(['Keywords', ', '.join(keywords)])
    ws.append(['Match mode', mode])
    ws.append(['Searched at', datetime.now().strftime('%Y-%m-%d %H:%M')])
    ws.append(['Total domains', total])
    ws.append([])
    ws.append(['TLD', 'Domains found'])
    for tld, labels in sorted(results.items(), key=lambda kv: -len(kv[1])):
        if labels:
            ws.append([f'.{tld}', len(labels)])

    # Domain sheet(s), split if they exceed Excel's row limit
    header = ['Domain', 'Name', 'TLD', 'Keyword'] + (ENRICH_COLUMNS if enriched else [])
    widths = {'Domain': 40, 'Name': 30, 'Keyword': 20, 'Registered': 12, 'Expires': 12, 'Registrar': 30,
              'Status': 30, 'Nameservers': 40, 'IP': 16, 'Hosting': 35, 'MX': 40, 'Email provider': 20,
              'HTTP status': 12, 'Final URL': 40, 'Notes': 40}
    sheet_num, rows_in_sheet, ws = 0, EXCEL_MAX_ROWS, None
    for tld in sorted(results):
        for label in results[tld]:
            if rows_in_sheet >= EXCEL_MAX_ROWS:
                sheet_num += 1
                ws = wb.create_sheet('Domains' if sheet_num == 1 else f'Domains {sheet_num}')
                for i, col in enumerate(header, 1):
                    ws.column_dimensions[get_column_letter(i)].width = widths.get(col, 10)
                ws.freeze_panes = 'A2'
                ws.append(header)
                rows_in_sheet = 0
            domain = f'{label}.{tld}'
            row    = [domain, label, tld, matched_keyword(label, keywords)]
            if enriched:
                info = enriched.get(domain, {})
                row += [info.get(col) for col in ENRICH_COLUMNS]
            ws.append(row)
            rows_in_sheet += 1

    if ws is None:
        ws = wb.create_sheet('Domains')
        ws.append(header)

    wb.save(path)


def search(keywords: list, tlds: list, mode: str, output: str, workers: int,
           enrich: bool = True, enrich_workers: int = 32, max_enrich: int = 5000):
    keywords = [k.lower().strip() for k in keywords if k.strip()]

    files = [os.path.join(ZONES_DIR, f) for f in os.listdir(ZONES_DIR) if f.endswith('.txt.gz')] if os.path.isdir(ZONES_DIR) else []
    if tlds:
        wanted = {t.lower().lstrip('.') for t in tlds}
        files  = [f for f in files if os.path.basename(f).split('.')[0] in wanted]
    if not files:
        sys.exit(f'No zone files found in {ZONES_DIR}. Run "download" first.')

    # Largest first so the big zones (.com) start immediately and don't finish last
    files.sort(key=os.path.getsize, reverse=True)
    log.info(f'Searching {len(files):,} zone file(s) for {keywords} (mode: {mode}) with {workers} worker(s)')

    results, start = {}, time.time()
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(search_zone, f, keywords, mode): f for f in files}
        for i, future in enumerate(as_completed(futures), 1):
            try:
                tld, labels = future.result()
                results[tld] = labels
                if labels:
                    log.info(f'[{i}/{len(files)}] .{tld}: {len(labels):,} match(es)')
            except Exception as e:
                log.warning(f'[{i}/{len(files)}] Error reading {futures[future]}: {e}')

    total = sum(len(v) for v in results.values())
    log.info(f'Found {total:,} domain(s) in {time.time() - start:,.0f}s')

    enriched = None
    if enrich and total > max_enrich:
        log.warning(f'Skipping enrichment: {total:,} domains is more than --max-enrich {max_enrich:,} '
                    f'(it would take a long time and hit registry rate limits). Narrow the search or raise the limit.')
    elif enrich and total:
        from domain_enrich import enrich as enrich_domains
        enriched = enrich_domains([f'{label}.{tld}' for tld, labels in results.items() for label in labels], enrich_workers)

    output = output or f'domains_{"_".join(keywords)[:50]}_{datetime.now():%Y%m%d_%H%M}.xlsx'
    write_excel(output, results, keywords, mode, enriched)
    log.info(f'Saved {os.path.abspath(output)}')


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='Download CZDS zone files and search them for keywords')
    sub    = parser.add_subparsers(dest='command', required=True)

    sub.add_parser('list', help='List the TLDs you have CZDS access to')

    dl = sub.add_parser('download', help='Download zone files from CZDS')
    dl.add_argument('--tlds', nargs='+', help='Only these TLDs (default: all you have access to)')
    dl.add_argument('-c', '--concurrency', type=int, default=3, help='Concurrent downloads (default: 3)')
    dl.add_argument('--force', action='store_true', help=f'Re-download even if a file is newer than {MAX_AGE_HOURS}h')

    sr = sub.add_parser('search', help='Search downloaded zone files and export to Excel')
    sr.add_argument('keywords', nargs='+', help='One or more keywords')
    sr.add_argument('--tlds', nargs='+', help='Only search these TLDs (default: all downloaded)')
    sr.add_argument('--mode', choices=['contains', 'prefix', 'suffix', 'exact'], default='contains',
                    help='How the keyword must match the name before the TLD (default: contains)')
    sr.add_argument('-o', '--output', help='Output .xlsx path')
    sr.add_argument('-w', '--workers', type=int, default=os.cpu_count(), help='Parallel processes')
    sr.add_argument('--no-enrich', action='store_true', help='Skip RDAP/DNS/HTTP lookups (domain names only)')
    sr.add_argument('--enrich-workers', type=int, default=32, help='Parallel lookup threads (default: 32)')
    sr.add_argument('--max-enrich', type=int, default=5000, help='Skip lookups if more matches than this (default: 5000)')

    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s  %(message)s', datefmt='%H:%M:%S', force=True)

    if args.command in ('list', 'download'):
        username = os.getenv('CZDS_USER') or input('ICANN Username: ')
        password = os.getenv('CZDS_PASS') or getpass.getpass('ICANN Password: ')
        if args.command == 'list':
            asyncio.run(list_zones(username, password))
        else:
            asyncio.run(download_zones(username, password, args.tlds, args.concurrency, args.force))
    else:
        search(args.keywords, args.tlds, args.mode, args.output, args.workers,
               not args.no_enrich, args.enrich_workers, args.max_enrich)


if __name__ == '__main__':
    main()
