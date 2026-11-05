#!/usr/bin/env python3
'''
Enrich domain names with free public data (no API keys):

    RDAP (registry)     -> registration / expiry date, registrar, status, nameservers
    DNS A + Team Cymru  -> IP, hosting provider (ASN owner)
    DNS MX              -> mail servers, email provider
    HTTP(S) request     -> status code, final URL after redirects

Used automatically by `domain_scraper.py search`, or standalone:
    python domain_enrich.py example.org wordsmith.app
'''

import json
import logging
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

import dns.resolver
import requests
import urllib3

urllib3.disable_warnings()  # Certificate errors are retried without verification and reported in Notes

CACHE_DIR      = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.cache')
BOOTSTRAP_URL  = 'https://data.iana.org/rdap/dns.json'
BOOTSTRAP_DAYS = 7    # Refresh the cached IANA bootstrap file weekly
RDAP_PER_HOST  = 3    # Concurrent requests per RDAP server, to stay under registry rate limits
HTTP_TIMEOUT   = (5, 10)
USER_AGENT     = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'

COLUMNS = ['Registered', 'Expires', 'Registrar', 'Status', 'Nameservers', 'IP', 'Hosting', 'ASN',
           'MX', 'Email provider', 'HTTP status', 'Final URL', 'Notes']

# MX hostname fragment -> provider
EMAIL_PROVIDERS = {
    'google.com': 'Google Workspace', 'googlemail.com': 'Google Workspace',
    'outlook.com': 'Microsoft 365', 'protection.outlook.com': 'Microsoft 365',
    'zoho.': 'Zoho', 'protonmail.ch': 'Proton Mail', 'mimecast': 'Mimecast',
    'pphosted.com': 'Proofpoint', 'messagelabs.com': 'Symantec', 'secureserver.net': 'GoDaddy',
    'emailsrvr.com': 'Rackspace', 'mailgun.org': 'Mailgun', 'sendgrid.net': 'SendGrid',
    'amazonaws.com': 'Amazon SES', 'icloud.com': 'iCloud', 'yandex': 'Yandex',
    'ovh.net': 'OVH', 'ionos': 'IONOS', 'registrar-servers.com': 'Namecheap',
    'privateemail.com': 'Namecheap', 'titan.email': 'Titan', 'fastmail': 'Fastmail',
    'hostinger': 'Hostinger', 'mx.cloudflare.net': 'Cloudflare Email Routing',
}

log = logging.getLogger('domain_scraper')

resolver = dns.resolver.Resolver()
resolver.timeout  = 3
resolver.lifetime = 6

_host_locks = {}
_host_locks_guard = threading.Lock()
_asn_cache = {}


# ---------------------------------------------------------------------------
# RDAP
# ---------------------------------------------------------------------------

def load_bootstrap() -> dict:
    '''TLD -> RDAP base URL, from IANA's bootstrap file (cached on disk).'''
    os.makedirs(CACHE_DIR, exist_ok=True)
    path = os.path.join(CACHE_DIR, 'rdap_dns.json')

    if not os.path.exists(path) or time.time() - os.path.getmtime(path) > BOOTSTRAP_DAYS * 86400:
        data = requests.get(BOOTSTRAP_URL, timeout=30).json()
        with open(path, 'w') as f:
            json.dump(data, f)
    with open(path) as f:
        data = json.load(f)

    return {tld: svc[1][0].rstrip('/') for svc in data['services'] for tld in svc[0]}


def host_semaphore(url: str) -> threading.Semaphore:
    host = urlparse(url).netloc
    with _host_locks_guard:
        return _host_locks.setdefault(host, threading.Semaphore(RDAP_PER_HOST))


def vcard_name(entity: dict) -> str:
    for item in (entity.get('vcardArray') or [None, []])[1]:
        if item and item[0] == 'fn':
            return item[3]
    return entity.get('handle', '')


def to_date(value: str):
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).date()
    except (AttributeError, ValueError):
        return value or None


def rdap_lookup(domain: str, servers: dict) -> dict:
    tld = domain.rsplit('.', 1)[-1]
    if tld not in servers:
        return {'Notes': f'no RDAP server for .{tld}'}

    url = f'{servers[tld]}/domain/{domain}'
    with host_semaphore(url):
        for attempt in range(4):
            r = requests.get(url, timeout=15, headers={'Accept': 'application/rdap+json'})
            if r.status_code == 429:
                time.sleep(int(r.headers.get('Retry-After', 0) or 0) or 2 ** (attempt + 1))
                continue
            break

    if r.status_code == 404:
        return {'Notes': 'RDAP: not found (possibly deleted)'}
    r.raise_for_status()
    data = r.json()

    events    = {e.get('eventAction'): e.get('eventDate') for e in data.get('events', [])}
    registrar = next((vcard_name(e) for e in data.get('entities', []) if 'registrar' in e.get('roles', [])), '')
    return {
        'Registered':  to_date(events.get('registration')),
        'Expires':     to_date(events.get('expiration')),
        'Registrar':   registrar,
        'Status':      ', '.join(data.get('status', [])),
        'Nameservers': ', '.join(sorted(n.get('ldhName', '').lower() for n in data.get('nameservers', []))),
    }


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def dns_txt(name: str) -> str:
    return b''.join(resolver.resolve(name, 'TXT')[0].strings).decode()


def asn_lookup(ip: str) -> tuple:
    '''IP -> (ASN, owner) via Team Cymru's free DNS service.'''
    if ip not in _asn_cache:
        try:
            # "13335 | 104.16.0.0/13 | US | arin | 2014-03-28"
            asn = dns_txt('.'.join(reversed(ip.split('.'))) + '.origin.asn.cymru.com').split('|')[0].strip().split()[0]
            # "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
            owner = dns_txt(f'AS{asn}.asn.cymru.com').split('|')[-1].strip()
            _asn_cache[ip] = (f'AS{asn}', owner)
        except Exception:
            _asn_cache[ip] = ('', '')
    return _asn_cache[ip]


def email_provider(mx_hosts: list) -> str:
    for host in mx_hosts:
        for fragment, provider in EMAIL_PROVIDERS.items():
            if fragment in host:
                return provider
    return 'Self-hosted / other' if mx_hosts else ''


def dns_lookup(domain: str) -> dict:
    info, notes = {}, []

    try:
        ip = resolver.resolve(domain, 'A')[0].to_text()
        asn, owner = asn_lookup(ip)
        info.update({'IP': ip, 'ASN': asn, 'Hosting': owner})
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        notes.append('no A record')
    except dns.exception.Timeout:
        notes.append('DNS timeout')

    try:
        mx = sorted((r.preference, str(r.exchange).rstrip('.').lower()) for r in resolver.resolve(domain, 'MX'))
        hosts = [h for _, h in mx if h]
        info.update({'MX': ', '.join(hosts), 'Email provider': email_provider(hosts)})
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        pass

    if notes:
        info['Notes'] = notes
    return info


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def http_check(domain: str) -> dict:
    headers = {'User-Agent': USER_AGENT}
    last_error = ''
    for scheme in ('https', 'http'):
        for verify in (True, False):
            try:
                with requests.get(f'{scheme}://{domain}', headers=headers, timeout=HTTP_TIMEOUT,
                                  allow_redirects=True, stream=True, verify=verify) as r:
                    info = {'HTTP status': r.status_code, 'Final URL': r.url}
                    if not verify:
                        info['Notes'] = ['invalid SSL certificate']
                    return info
            except requests.exceptions.SSLError:
                last_error = 'SSL error'
                continue        # Retry same scheme without certificate verification
            except requests.exceptions.RequestException as e:
                last_error = type(e).__name__
                break           # Try the next scheme
    return {'HTTP status': 'no response', 'Notes': [f'HTTP: {last_error}']}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def enrich_one(domain: str, servers: dict) -> dict:
    row, notes = {}, []
    for step in (lambda: rdap_lookup(domain, servers), lambda: dns_lookup(domain), lambda: http_check(domain)):
        try:
            result = step()
        except Exception as e:
            notes.append(f'{type(e).__name__}: {e}'[:120])
            continue
        n = result.pop('Notes', [])
        notes.extend([n] if isinstance(n, str) else n)
        row.update(result)
    row['Notes'] = '; '.join(notes)
    return row


def enrich(domains: list, workers: int = 32) -> dict:
    '''Returns {domain: {column: value}} for every domain.'''
    from tqdm import tqdm

    servers = load_bootstrap()
    results = {}
    log.info(f'Enriching {len(domains):,} domain(s) (RDAP, DNS, HTTP) with {workers} threads...')

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(enrich_one, d, servers): d for d in domains}
        for future in tqdm(as_completed(futures), total=len(futures), desc='Enriching', unit='domain'):
            results[futures[future]] = future.result()
    return results


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s  %(message)s', datefmt='%H:%M:%S')
    for domain, info in enrich([d.lower() for d in sys.argv[1:]]).items():
        print(f'\n{domain}')
        for col in COLUMNS:
            print(f'  {col:15} {info.get(col, "")}')
