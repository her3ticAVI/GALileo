#!/usr/bin/env python3

import argparse
import ipaddress
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import requests
from requests.auth import HTTPBasicAuth

try:
    from requests_ntlm import HttpNtlmAuth
    HAVE_NTLM = True
except ImportError:
    HAVE_NTLM = False

requests.packages.urllib3.disable_warnings()

EWS_PATH = "/EWS/Exchange.asmx"

FINDPEOPLE = """<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
 <soap:Header><t:RequestServerVersion Version="Exchange2013"/></soap:Header>
 <soap:Body><m:FindPeople>
  <m:PersonaShape><t:BaseShape>IdOnly</t:BaseShape>
   <t:AdditionalProperties><t:FieldURI FieldURI="persona:EmailAddress"/></t:AdditionalProperties></m:PersonaShape>
  <m:IndexedPageItemView MaxEntriesReturned="100" BasePoint="Beginning" Offset="{off}"/>
  <m:ParentFolderId><t:DistinguishedFolderId Id="directory"/></m:ParentFolderId>
  <m:QueryString>{q}</m:QueryString>
 </m:FindPeople></soap:Body>
</soap:Envelope>"""

RESOLVENAMES = """<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
 <soap:Header><t:RequestServerVersion Version="Exchange2013"/></soap:Header>
 <soap:Body><m:ResolveNames ReturnFullContactData="true" SearchScope="ActiveDirectory">
  <m:UnresolvedEntry>{q}</m:UnresolvedEntry></m:ResolveNames></soap:Body>
</soap:Envelope>"""

EMAIL_RE = re.compile(r"<t:EmailAddress>([^<]+@[^<]+)</t:EmailAddress>", re.I)
PERSONA_RE = re.compile(r"<t:Persona>", re.I)
VER_RE = re.compile(
    r'ServerVersionInfo[^>]*?MajorVersion="(\d+)"[^>]*?MinorVersion="(\d+)"'
    r'[^>]*?MajorBuildNumber="(\d+)"[^>]*?MinorBuildNumber="(\d+)"', re.I)

PRODUCT = {("15", "2"): "Exchange 2019 / SE", ("15", "1"): "Exchange 2016",
           ("15", "0"): "Exchange 2013", ("14", "3"): "Exchange 2010"}

_print_lock = threading.Lock()
_results_lock = threading.Lock()
_emails = set()


def log(host, port, tag, msg):
    sym = {"+": "[+]", "-": "[-]", "*": "[*]", "!": "[!]"}.get(tag, "[*]")
    with _print_lock:
        print("GAL   {:<16} {:<5} {} {}".format(host, port, sym, msg))


def expand_targets(target):
    """Accept an IP, CIDR, hostname, or @file and return a list of hosts."""
    items = []
    if target.startswith("@"):
        with open(target[1:]) as f:
            items = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    else:
        items = [target]
    hosts = []
    for it in items:
        try:
            net = ipaddress.ip_network(it, strict=False)
            if net.num_addresses > 1:
                hosts.extend(str(h) for h in net.hosts())
            else:
                hosts.append(str(net.network_address))
        except ValueError:
            hosts.append(it)  # hostname
    return hosts


def make_auth(args):
    user = "{}\\{}".format(args.domain, args.username) if args.domain else args.username
    want_ntlm = args.auth == "ntlm" or (args.auth == "auto" and HAVE_NTLM)
    if want_ntlm:
        if not HAVE_NTLM:
            sys.exit("[!] NTLM requested but requests_ntlm is not installed "
                     "(pip install requests_ntlm), or use --auth basic")
        return HttpNtlmAuth(user, args.password), "ntlm"
    return HTTPBasicAuth(user, args.password), "basic"


def new_session(args):
    s = requests.Session()
    s.trust_env = False          # ignore http(s)_proxy env - internal targets
    s.proxies = {}
    s.verify = not args.insecure
    return s


def post(session, url, body, timeout, auth=None):
    return session.post(url, data=body.encode("utf-8"), auth=auth, timeout=timeout,
                        headers={"Content-Type": "text/xml; charset=utf-8"})


def detect_ews(host, port, timeout, insecure):
    """Unauthenticated probe. Return a short label if the host exposes EWS, else None."""
    url = "https://{}:{}{}".format(host, port, EWS_PATH)
    try:
        r = requests.get(url, timeout=timeout, verify=not insecure,
                         proxies={}, allow_redirects=False)
    except requests.RequestException:
        return None
    if r.status_code in (401, 403):
        wa = r.headers.get("WWW-Authenticate", "")
        if "NTLM" in wa or "Negotiate" in wa or "Basic" in wa:
            return "auth required"
        return "EWS (status {})".format(r.status_code)
    if r.status_code == 200 and ("definitions" in r.text.lower() or "wsdl" in r.text.lower()):
        return "EWS WSDL (anonymous)"
    return None


def version_from(text):
    m = VER_RE.search(text)
    if not m:
        return None
    maj, minr, bld, mbld = m.groups()
    prod = PRODUCT.get((maj, minr), "")
    v = "{}.{}.{}.{}".format(maj, minr, bld, mbld)
    return "{} ({})".format(v, prod) if prod else v


def harvest(text):
    return {e.lower() for e in EMAIL_RE.findall(text)}


def dump_findpeople(session, url, auth, timeout):
    import string
    found = set()
    for q in string.ascii_lowercase:
        off = 0
        while True:
            try:
                r = post(session, url, FINDPEOPLE.format(q=q, off=off), timeout, auth)
            except requests.RequestException:
                break
            n = len(PERSONA_RE.findall(r.text))
            found |= harvest(r.text)
            if n < 100:
                break
            off += 100
    return found


def dump_resolvenames(session, url, auth, timeout):
    import string
    found = set()
    for q in string.ascii_lowercase:
        try:
            r = post(session, url, RESOLVENAMES.format(q=q), timeout, auth)
        except requests.RequestException:
            continue
        found |= harvest(r.text)
    return found


def process_host(host, args):
    port = args.port
    label = detect_ews(host, port, args.timeout, args.insecure)
    if not label:
        if args.verbose:
            log(host, port, "-", "no EWS")
        return
    log(host, port, "*", "Exchange EWS detected ({})".format(label))

    if args.discover_only or not args.username:
        return

    url = "https://{}:{}{}".format(host, port, EWS_PATH)
    session = new_session(args)
    auth, auth_name = make_auth(args)

    try:
        probe = post(session, url, RESOLVENAMES.format(q="a"), args.timeout, auth)
    except requests.RequestException as e:
        log(host, port, "-", "connection failed: {}".format(e))
        return
    if probe.status_code == 401:
        log(host, port, "-", "{} auth failed (401)".format(auth_name))
        return

    ver = version_from(probe.text)
    log(host, port, "+", "authenticated ({}){}".format(
        auth_name, " - " + ver if ver else ""))

    method = args.method
    if method == "auto":
        try:
            fp = post(session, url, FINDPEOPLE.format(q="a", off=0), args.timeout, auth)
            method = "findpeople" if PERSONA_RE.search(fp.text) else "resolvenames"
        except requests.RequestException:
            method = "resolvenames"

    if method == "findpeople":
        emails = dump_findpeople(session, url, auth, args.timeout)
        if not emails:
            emails = dump_resolvenames(session, url, auth, args.timeout)
    else:
        emails = dump_resolvenames(session, url, auth, args.timeout)

    with _results_lock:
        _emails.update(emails)
    log(host, port, "+", "dumped {} addresses (method: {})".format(len(emails), method))


def main():
    ap = argparse.ArgumentParser(
        prog="galileo.py",
        description="GALileo - dump the Global Address List from on-prem Exchange "
                    "with one mailbox credential. No Domain Controller required.")
    ap.add_argument("target", help="host, IP, CIDR (10.0.0.0/24), or @file-of-hosts")
    ap.add_argument("-u", "--username", help="mailbox username")
    ap.add_argument("-p", "--password", help="password")
    ap.add_argument("-d", "--domain", default="", help="AD/NetBIOS domain, e.g. example.com")
    ap.add_argument("--auth", choices=["auto", "ntlm", "basic"], default="auto")
    ap.add_argument("--method", choices=["auto", "findpeople", "resolvenames"], default="auto")
    ap.add_argument("--port", type=int, default=443, help="EWS port (default 443)")
    ap.add_argument("-o", "--output", default="gal", help="output file prefix (default: gal)")
    ap.add_argument("-t", "--threads", type=int, default=16, help="concurrent hosts (default 16)")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--discover-only", action="store_true", help="only find EWS servers, do not dump")
    ap.add_argument("-k", "--insecure", action="store_true", default=True,
                    help="skip TLS verification (default on)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.username and not args.password:
        ap.error("-u given without -p")

    hosts = expand_targets(args.target)
    print("[*] GALileo  |  targets: {}  port: {}  mode: {}".format(
        len(hosts), args.port,
        "discover" if (args.discover_only or not args.username) else "dump"))
    if args.username and not HAVE_NTLM and args.auth in ("auto", "ntlm"):
        print("[!] requests_ntlm not installed - falling back to Basic "
              "(pip install requests_ntlm for NTLM).")

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        ex.map(lambda h: process_host(h, args), hosts)

    if args.username and not args.discover_only:
        emails = sorted(_emails)
        users = sorted({e.split("@", 1)[0] for e in emails})
        with open(args.output + "_emails.txt", "w") as f:
            f.write("\n".join(emails) + ("\n" if emails else ""))
        with open(args.output + "_users.txt", "w") as f:
            f.write("\n".join(users) + ("\n" if users else ""))
        print("[+] {} unique addresses -> {}_emails.txt".format(len(emails), args.output))
        print("[+] {} unique users     -> {}_users.txt".format(len(users), args.output))


if __name__ == "__main__":
    main()
