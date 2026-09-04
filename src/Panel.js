import { connect } from "cloudflare:sockets";

const tbTrafficMap = new Map();
const tbConnCount = new Map();
const tbLastActive = new Map();
const tbLastWrite = new Map();
const tbWriteLock = new Map();
const tbDnsCache = new Map();
const tbReqCache = new Map();
const tbLoginAttempts = new Map();
let tbReqTotal = 0;
let tbLastReqWrite = 0;
let CF_REQ_CACHE = { day: "", base: 0, fetchedAt: 0, delta: 0 };
const TB_DNS_TTL = 5 * 60 * 1000;
const DOH_RESOLVER = atob(String.fromCharCode(97,72,82,48,99,72,77,54,76,121,57,106,98,71,57,49,90,71,90,115,89,88,74,108,76,87,82,117,99,121,53,106,98,50,48,118,90,71,53,122,76,88,70,49,90,88,74,53));
const UPSTREAM_BUNDLE_TARGET_BYTES = 128 * 1024;
const UPSTREAM_QUEUE_MAX_BYTES = 16 * 1024 * 1024;
const UPSTREAM_QUEUE_MAX_ITEMS = 4096;
const DOWNSTREAM_GRAIN_BYTES = 32 * 1024;
const TB_DNS_MAX = 2048;
const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();
const TLS_PORTS = new Set(["443", "2053", "2083", "2087", "2096", "8443"]);
let _tbProxyCursor = { list: [], at: 0, fetchedAt: 0 };

const TREX_FRAG_QUERY = "&fragment=" + encodeURIComponent("tlshello,5,94,1,0") + "&fragment2=" + encodeURIComponent("1-1,109,1,1,355");
const DEFAULT_FRAG_QUERY = "&fragment=" + encodeURIComponent("tlshello,100-200,1-1,100-200");
const TREX_FRAG_JSON = JSON.stringify({
	mode: "flux",
	packets: "tlshello",
	length: "5,94,1",
	interval: "0",
	maxSplit: "0",
	dual: true,
	packets2: "1-1",
	length2: "109,1",
	interval2: "1",
	maxSplit2: "355",
	protocols: "vless",
});
const DEFAULT_FRAG_JSON = JSON.stringify({
	mode: "default",
	packets: "tlshello",
	length: "100-200",
	interval: "1-1",
	maxSplit: "100-200",
	protocols: "vless",
});
function isTrexFrag(userOrFrag) {
	try {
		let raw = userOrFrag;
		if (raw && typeof raw === "object" && raw.frag_len !== undefined) raw = raw.frag_len;
		if (raw == null || raw === "") return false;
		const s = String(raw);
		if (s.includes("trex") || s.includes("flux") || s.includes("packets2") || s.includes("5,94,1") || s.includes('"dual":true') || s.includes('"dual": true')) return true;
		if (!s.trim().startsWith("{")) return false;
		const f = JSON.parse(s);
		if (!f || typeof f !== "object") return false;
		const mode = String(f.mode || "").toLowerCase();
		return mode === "trex" || mode === "flux" || f.dual === true || !!f.packets2;
	} catch (e) {
		return false;
	}
}

function toBoldSans(str) {
	let out = "";
	for (const ch of String(str || "")) {
		const c = ch.codePointAt(0);
		if (c >= 65 && c <= 90) out += String.fromCodePoint(0x1D5D4 + (c - 65));
		else if (c >= 97 && c <= 122) out += String.fromCodePoint(0x1D5EE + (c - 97));
		else if (c >= 48 && c <= 57) out += String.fromCodePoint(0x1D7EC + (c - 48));
		else out += ch;
	}
	return out;
}
function flagFromCC(cc) {
	try {
		const code = String(cc || "").trim().toUpperCase();
		if (code.length !== 2 || code === "XX" || code === "ZZ") return "";
		return String.fromCodePoint(...code.split("").map((ch) => 127397 + ch.charCodeAt(0)));
	} catch (e) {
		return "";
	}
}
function buildConfigRemark(user, protocol, countryCode) {
	const uname = String((user && user.username) || "user");
	const m = uname.match(/^TrexBridge[-_]?(.+)$/i);
	let namePart;
	if (m) {
		const rnd = String(m[1] || "").replace(/[^a-zA-Z0-9]/g, "");
		namePart = (rnd.slice(0, 3) || "x").toLowerCase();
	} else {
		namePart = uname;
	}
	return "🦖 - " + toBoldSans("TrexBridge") + "-" + toBoldSans(namePart);
}

function parseUserIps(user, host) {
	const out = [];
	const seen = new Set();
	const push = (v) => {
		const x = String(v || "").trim();
		if (!x) return;
		const key = x.toLowerCase();
		if (seen.has(key)) return;
		seen.add(key);
		out.push(x);
	};
	if (user && user.ips) {
		String(user.ips)
			.split(/[\n,\r]+/)
			.map((s) => s.trim())
			.filter(Boolean)
			.forEach((ip) => {
				const v = String(ip).trim();
				if (!v) return;
				if (host && v.toLowerCase() === String(host).toLowerCase()) return;
				if (/\.workers\.dev$/i.test(v)) return;
				push(v);
			});
	}
	// Always include worker hostname so clients can connect even if Clean IPs are dead
	if (host) push(host);
	if (!out.length && host) push(host);
	return out;
}
function parseUserPorts(user) {
	const ports = String((user && user.port) || "443")
		.split(",")
		.map((p) => p.trim())
		.filter(Boolean);
	return ports.length ? ports : ["443"];
}
function buildFragmentQueryFromUser(user) {
	let protos = ["vless"];
	let useFlux = true;
	try {
		let raw = user && user.frag_len != null ? user.frag_len : "";
		if (raw && typeof raw === "object") {
			try { raw = JSON.stringify(raw); } catch (eO) { raw = ""; }
		}
		const s = String(raw || "").trim();
		if (s) {
			// explicit default mode only
			let isDefault = false;
			if (s.charAt(0) === "{") {
				try {
					const f = JSON.parse(s);
					if (f && typeof f === "object") {
						const mode = String(f.mode || "").toLowerCase();
						if (mode === "default" || mode === "normal") isDefault = true;
						if (f.protocols) {
							protos = String(f.protocols).split(",").map(function (p) { return p.trim().toLowerCase(); }).filter(Boolean);
							if (!protos.length) protos = ["vless"];
						}
					}
				} catch (e2) {}
			} else if (s.indexOf("default") >= 0 && s.indexOf("flux") < 0 && s.indexOf("trex") < 0 && s.indexOf("packets2") < 0) {
				isDefault = true;
			}
			useFlux = !isDefault;
		}
	} catch (e) {}
	return { query: useFlux ? TREX_FRAG_QUERY : DEFAULT_FRAG_QUERY, protos: protos, flux: useFlux };
}
function buildAllConfigLinks(user, host) {
	const ips = parseUserIps(user, host);
	const ports = parseUserPorts(user);
	const fp = (user && user.fingerprint) || "chrome";
	const path = encodeURIComponent("/api/ws");
	const frag = buildFragmentQueryFromUser(user);
	// ALWAYS attach fragment — never omit (flux default)
	const userFrag = (frag && frag.flux === false) ? DEFAULT_FRAG_QUERY : TREX_FRAG_QUERY;
	const protos = frag.protos && frag.protos.length ? frag.protos : ["vless"];
	const uuid = (user && user.uuid) || "";
	const links = [];
	for (const ip of ips) {
		for (const port of ports) {
			const isTls = TLS_PORTS.has(String(port));
			const tlsVal = isTls ? "tls" : "none";
			if (protos.includes("vless")) {
				const remark = buildConfigRemark(user, "vless", "");
				// Original Trex order: path, security, encryption, insecure, host, fp, type, allowInsecure, sni, fragment...
				links.push(
					"vless://" + uuid + "@" + ip + ":" + port +
					"?path=" + path +
					"&security=" + tlsVal +
					"&encryption=none&insecure=0&host=" + host +
					"&fp=" + fp +
					"&type=ws&allowInsecure=0&sni=" + host +
					"&ed=2560" +
					userFrag +
					"#" + encodeURIComponent(remark)
				);
			}
			if (protos.includes("trojan")) {
				const alpn = tlsVal === "tls" ? "&alpn=http%2F1.1" : "";
				const remark = buildConfigRemark(user, "trojan", "");
				links.push(
					"trojan://" + uuid + "@" + ip + ":" + port +
					"?path=" + path +
					"&security=" + tlsVal +
					"&type=ws&host=" + host +
					"&fp=" + fp +
					"&sni=" + host +
					"&allowInsecure=0" + alpn +
					"&ed=2560" +
					userFrag +
					"#" + encodeURIComponent(remark)
				);
			}
		}
	}
	return links;
}

function safeDecodeURI(value) {
	try {
		return decodeURIComponent(value);
	} catch (e) {
		return value;
	}
}
async function readJsonBody(request) {
	try {
		const body = await request.json();
		return body && typeof body === "object" ? body : {};
	} catch (e) {
		return {};
	}
}
const CLEAN_IP_JSON_URL = 'https://raw.githubusercontent.com/icubaby/TrexBridge/refs/heads/main/data/CleanIP.json';
const PANEL_REPO_BASE = 'https://raw.githubusercontent.com/icubaby/TrexBridge/refs/heads/main';
async function fetchWithFallback(path, options = {}) {
	const p = (path || "").replace(/^\/+/, "");
	if (p === "CleanIP.json" || p === "data/CleanIP.json") {
		return await fetch(CLEAN_IP_JSON_URL + (options && options.cache === "no-store" ? "" : "?t=" + Date.now()), options);
	}
	const customUrl = PANEL_REPO_BASE + "/" + p;
	return await fetch(customUrl, options);
}

async function fetchCleanIpData() {
	try {
		const res = await fetchWithFallback("data/CleanIP.json", { cache: "no-store" });
		if (!res || !res.ok) return {};
		const data = await res.json();
		return data && typeof data === "object" ? data : {};
	} catch (e) {
		return {};
	}
}

function findOpList(data, key) {
	if (!data || typeof data !== "object" || !key) return [];
	if (Array.isArray(data[key])) return data[key];
	const want = String(key).toUpperCase();
	for (const k of Object.keys(data)) {
		if (String(k).toUpperCase() === want && Array.isArray(data[k])) return data[k];
	}
	return [];
}

function pickCleanIps(data, operator, count) {
	const opOrder = ["Irancell", "Rightel", "Shatel", "MCI", "Telecom", "Aptel", "SamanTel", "Pishgaman", "Fiber", "Asiatech"];
	const norm = (ip) => String(ip || "").trim();
	const uniquePush = (arr, ip) => {
		const v = norm(ip);
		if (!v) return;
		if (!arr.includes(v)) arr.push(v);
	};
	let pool = [];
	const op = String(operator || "all");
	const opUp = op.toUpperCase();
	if (opUp === "ALL" || op === "") {
		for (const k of opOrder) {
			const list = (findOpList(data, k) || []).map(norm).filter(Boolean);
			const uniq = Array.from(new Set(list));
			if (uniq.length) uniquePush(pool, uniq[Math.floor(Math.random() * uniq.length)]);
		}
		for (const k of Object.keys(data || {})) {
			if (String(k).toUpperCase() === "ALL") continue;
			const list = Array.isArray(data[k]) ? data[k] : [];
			for (const ip of list) uniquePush(pool, ip);
		}
	} else {
		const list = (findOpList(data, op) || []).map(norm).filter(Boolean);
		pool = Array.from(new Set(list));
	}
	for (let i = pool.length - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1));
		const t = pool[i];
		pool[i] = pool[j];
		pool[j] = t;
	}
	const want = Math.max(1, Number(count) || 10);
	return pool.slice(0, Math.min(want, pool.length));
}

let localLastAutoResetCheck = 0;
async function checkAutoResets(env, ctx) {
	const now = Date.now();
	if (now - localLastAutoResetCheck < 3600000) return;
	try {
		const cache = caches.default;
		const cacheReq = new Request("https://internal.app/cache/reset");
		if (await cache.match(cacheReq)) return;
		const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'last_auto_reset_check'").first();
		const dbLastCheck = row ? parseInt(row.value) || 0 : 0;
		if (now - dbLastCheck < 3600000) {
			localLastAutoResetCheck = dbLastCheck;
			const ttl = Math.floor((3600000 - (now - dbLastCheck)) / 1000);
			if (ttl > 0 && ctx) ctx.waitUntil(cache.put(cacheReq, new Response("1", { headers: { "Cache-Control": `max-age=${ttl}` } })));
			return;
		}
		await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('last_auto_reset_check', ?)").bind(String(now)).run();
		localLastAutoResetCheck = now;
		if (ctx) ctx.waitUntil(cache.put(cacheReq, new Response("1", { headers: { "Cache-Control": "max-age=3600" } })));
		const todayUtc = Math.floor(now / 86400000) * 86400000;
		await env.DB.prepare(`UPDATE users SET used_gb = 0, is_active = 1, last_reset_vol_time = ? WHERE auto_reset_vol_days > 0 AND ? >= (last_reset_vol_time + (auto_reset_vol_days * 86400000))`).bind(todayUtc, todayUtc).run();
		await env.DB.prepare(`UPDATE users SET used_req = 0, is_active = 1, last_reset_req_time = ? WHERE auto_reset_req_days > 0 AND ? >= (last_reset_req_time + (auto_reset_req_days * 86400000))`).bind(todayUtc, todayUtc).run();
	} catch (e) {}
}
let localLastIpRotateCheck = 0;
async function checkAutoRotates(env, ctx) {
	const now = Date.now();
	if (now - localLastIpRotateCheck < 60000) return;
	try {
		const cache = caches.default;
		const cacheReq = new Request("https://internal.app/cache/rotate");
		if (await cache.match(cacheReq)) return;
		const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'last_ip_rotate_check'").first();
		const dbLastCheck = row ? parseInt(row.value) || 0 : 0;
		if (now - dbLastCheck < 60000) {
			localLastIpRotateCheck = dbLastCheck;
			const ttl = Math.floor((60000 - (now - dbLastCheck)) / 1000);
			if (ttl > 0 && ctx) ctx.waitUntil(cache.put(cacheReq, new Response("1", { headers: { "Cache-Control": `max-age=${ttl}` } })));
			return;
		}
		await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('last_ip_rotate_check', ?)").bind(String(now)).run();
		localLastIpRotateCheck = now;
		if (ctx) ctx.waitUntil(cache.put(cacheReq, new Response("1", { headers: { "Cache-Control": "max-age=60" } })));
		const { results: usersToRotate } = await env.DB.prepare("SELECT * FROM users WHERE auto_rotate_ip = 1 AND ? >= (last_rotate_time + (rotate_time * 60000))").bind(now).all();
		if (!usersToRotate || usersToRotate.length === 0) return;
				const res = await fetchWithFallback("data/CleanIP.json");
		if (!res.ok) return;
		let cachedIpsData = {};
		try {
			const json = await res.json();
			if (json && typeof json === "object") {
				Object.keys(json).forEach((k) => {
					if (Array.isArray(json[k]) && json[k].length) cachedIpsData[k] = json[k];
				});
			}
		} catch (e) {
			return;
		}
		const stmts = [];
		for (const u of usersToRotate) {
			let availableIps = [];
			if (u.ip_operator === "all") {
				Object.values(cachedIpsData).forEach((ips) => (availableIps = availableIps.concat(ips)));
			} else {
				availableIps = cachedIpsData[u.ip_operator] || [];
			}
			availableIps = [...new Set(availableIps)];
			let count = u.ip_count || 20;
			let selectedIps = [];
			if (count >= availableIps.length) {
				selectedIps = availableIps;
			} else {
				const shuffled = availableIps.slice();
				for (let i = shuffled.length - 1; i > 0; i--) {
					const j = Math.floor(Math.random() * (i + 1));
					[shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
				}
				selectedIps = shuffled.slice(0, count);
			}
			if (selectedIps.length > 0) {
				stmts.push(env.DB.prepare("UPDATE users SET ips = ?, last_rotate_time = ? WHERE id = ?").bind(selectedIps.join("\n"), now, u.id));
			}
		}
		if (stmts.length > 0) {
			const batchSize = 50;
			for (let i = 0; i < stmts.length; i += batchSize) {
				await env.DB.batch(stmts.slice(i, i + batchSize));
			}
		}
	} catch (e) {}
}
let cachedVipCountries = [];
let lastVipCountriesFetch = 0;
async function replaceBrokenProxy(username, env, oldProxy) {
	try {
		if (tbWriteLock.get(username + "_proxy_rotate")) return;
		tbWriteLock.set(username + "_proxy_rotate", true);
		const user = await env.DB.prepare("SELECT id, user_socks5, auto_rotate_user_proxy FROM users WHERE username = ?").bind(username).first();
		if (!user || user.auto_rotate_user_proxy !== 1 || !user.user_socks5) {
			tbWriteLock.delete(username + "_proxy_rotate");
			return;
		}
		let proxyList = [];
		let isArrayMode = false;
		try {
			if (user.user_socks5.trim().startsWith("[")) {
				proxyList = JSON.parse(user.user_socks5);
				isArrayMode = true;
			} else {
				proxyList = [user.user_socks5];
			}
		} catch (e) {
			proxyList = [user.user_socks5];
		}
		let matchIndex = -1;
		for (let i = 0; i < proxyList.length; i++) {
			let itemStr = typeof proxyList[i] === "object" && proxyList[i] !== null ? proxyList[i].proxy : proxyList[i];
			if (itemStr === oldProxy) {
				matchIndex = i;
				break;
			}
		}
		if (matchIndex === -1) {
			tbWriteLock.delete(username + "_proxy_rotate");
			return;
		}
		let countryCode = typeof proxyList[matchIndex] === "object" && proxyList[matchIndex] !== null && proxyList[matchIndex].country ? proxyList[matchIndex].country : "all";
		try {
			const payload = new TextEncoder().encode("GET /json/?fields=countryCode HTTP/1.1\r\nHost: ip-api.com\r\nConnection: close\r\n\r\n");
			const s = await connectProxy(oldProxy, "ip-api.com", 80, payload);
			const reader = s.readable.getReader();
			let resStr = "";
			const dec = new TextDecoder();
			const timeoutId = setTimeout(() => {
				try {
					s.close();
				} catch (e) {}
			}, 2000);
			try {
				while (true) {
					const res = await reader.read();
					if (res.done || !res.value) break;
					resStr += dec.decode(res.value, { stream: true });
					if (resStr.includes("countryCode")) break;
				}
			} finally {
				clearTimeout(timeoutId);
				try {
					s.close();
				} catch (e) {}
			}
			const jsonMatch = resStr.match(/\{[^}]*"countryCode"\s*:\s*"([^"]+)"[^}]*\}/);
			if (jsonMatch && jsonMatch[1]) countryCode = jsonMatch[1];
		} catch (e) {}
		if (countryCode === "all") {
			try {
				let remain = oldProxy.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
				if (remain.includes("@")) remain = remain.substring(remain.lastIndexOf("@") + 1);
				if (remain.startsWith("[")) remain = remain.substring(1, remain.indexOf("]"));
				else if (remain.includes(":")) remain = remain.substring(0, remain.lastIndexOf(":"));
				const geoRes = await fetch(`http://ip-api.com/json/${remain}?fields=countryCode`);
				const geoData = await geoRes.json();
				if (geoData && geoData.countryCode) countryCode = geoData.countryCode;
			} catch (e) {}
		}
		let newProxy = null;
		const upperCountry = countryCode.toUpperCase();
		const sources = [];
		const isOldProxyVIP = oldProxy.includes("@");
		if (cachedVipCountries.length === 0 || Date.now() - lastVipCountriesFetch > 3600000) {
			try {
				const ghRes = await fetchWithFallback("vip-list", {
					headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" },
				});
				if (ghRes.ok) {
					const files = await ghRes.json();
					cachedVipCountries = files.filter((f) => f.name.endsWith(".txt")).map((f) => f.name.replace(".txt", "").toUpperCase());
					lastVipCountriesFetch = Date.now();
				}
			} catch (e) {}
		}
		let fallbackVIPs = cachedVipCountries.length > 0 ? [...cachedVipCountries] : ["DE", "US", "GB", "NL", "FR", "TR"];
		for (let i = fallbackVIPs.length - 1; i > 0; i--) {
			const j = Math.floor(Math.random() * (i + 1));
			[fallbackVIPs[i], fallbackVIPs[j]] = [fallbackVIPs[j], fallbackVIPs[i]];
		}
		if (upperCountry !== "ALL" && upperCountry !== "UN") {
			sources.push({ url: `proxy_vip/${upperCountry}.txt`, type: "repo" });
		}
		for (const fc of fallbackVIPs) {
			if (fc !== upperCountry) {
				sources.push({ url: `proxy_vip/${fc}.txt`, type: "repo" });
			}
		}
		if (!isOldProxyVIP) {
			if (upperCountry !== "ALL" && upperCountry !== "UN") {
				sources.push({ url: `proxy/${upperCountry}.txt`, type: "repo" });
			}
			sources.push({ url: `proxy/ALL.txt`, type: "repo" });
		}
		for (const src of sources) {
			try {
				const res = await fetchWithFallback(src.url);
				if (!res.ok) continue;
				const text = await res.text();
				const lines = text
					.split("\n")
					.map((l) => l.trim())
					.filter((l) => l.length > 5);
				if (lines.length > 0) {
					for (let i = lines.length - 1; i > 0; i--) {
						const j = Math.floor(Math.random() * (i + 1));
						[lines[i], lines[j]] = [lines[j], lines[i]];
					}
					const testBatch = lines.slice(0, 3).flatMap((line) => {
						if (line.match(/^(socks4|socks5|socks|http|https|tg):\/\//i) || line.includes("t.me/socks")) {
							return [line];
						}
						if (src.type === "socks5") return [`socks5://${line}`];
						if (src.type === "http") return [`http://${line}`];
						return [`socks5://${line}`, `http://${line}`];
					});
					try {
						newProxy = await Promise.any(
							testBatch.map((p) => {
								return new Promise(async (resolve, reject) => {
									let sock = null;
									const timeoutId = setTimeout(() => {
										try {
											sock && sock.close();
										} catch (e) {}
										reject(new Error("timeout"));
									}, 3000);
									try {
										const payload = TEXT_ENCODER.encode("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n");
										sock = await connectProxy(p, "1.1.1.1", 80, payload);
										const reader = sock.readable.getReader();
										const res = await reader.read();
										clearTimeout(timeoutId);
										try {
											sock.close();
										} catch (e) {}
										if (res.done || !res.value) reject(new Error("empty"));
										else resolve(p);
									} catch (e) {
										clearTimeout(timeoutId);
										try {
											sock && sock.close();
										} catch (err) {}
										reject(e);
									}
								});
							}),
						);
					} catch (e) {
						continue;
					}
					if (newProxy) {
						break;
					}
				}
			} catch (e) {}
		}
		if (newProxy) {
			let finalProxyVal = newProxy;
			if (isArrayMode) {
				if (typeof proxyList[matchIndex] === "object" && proxyList[matchIndex] !== null) {
					proxyList[matchIndex].proxy = newProxy;
				} else {
					proxyList[matchIndex] = newProxy;
				}
				finalProxyVal = JSON.stringify(proxyList);
			}
			await env.DB.prepare("UPDATE users SET user_socks5 = ? WHERE id = ?").bind(finalProxyVal, user.id).run();
		}
	} catch (e) {
	} finally {
		tbWriteLock.delete(username + "_proxy_rotate");
	}
}

/* ===================== Telegram Bot ===================== */

/* Telegram bot logic removed — panel only */
async function tgSendDailyReport(env) {
	return { ok: false, reason: "disabled" };
}





const PANEL_ENC_K = new Uint8Array([47, 145, 74, 211, 8, 126, 197, 22]);
function panelUtf8ToBytes(str) {
	return new TextEncoder().encode(str);
}
function panelBytesToBase64(bytes) {
	let binary = "";
	const chunk = 0x8000;
	for (let i = 0; i < bytes.length; i += chunk) {
		binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
	}
	return btoa(binary);
}
function panelEncodePayload(bytes, k) {
	const out = new Uint8Array(bytes.length);
	for (let i = 0; i < bytes.length; i++) {
		let x = bytes[i] ^ k[i % k.length];
		x = ((x << 4) | (x >> 4)) & 255;
		x = (x + i * 3 + k[(i + 3) % k.length]) & 255;
		out[i] = x;
	}
	return panelBytesToBase64(out);
}
function preparePanelSourceForEncode(raw) {
	let s = String(raw || "").replace(/^\uFEFF/, "").replace(/\r\n/g, "\n");
	s = s.replace(/^\s*import\s*[\s\S]*?from\s*["']cloudflare:sockets["']\s*;?\s*/gm, "");
	s = s.replace(/import\s*\{[^}]*\}\s*from\s*["']cloudflare:sockets["']\s*;?/g, "");
	s = s.replace(/^[ \t]*import\b[^\n]*cloudflare:sockets[^\n]*$/gm, "");
	return s;
}
function buildEncodedWorkerFromSource(cleanSource) {
	const prepared = preparePanelSourceForEncode(cleanSource);
	if (!prepared || prepared.length < 500) throw new Error("Panel source too short");
	// Plain ES module deploy (no new Function encode) — reliable on Cloudflare
	return 'import { connect } from "cloudflare:sockets";\n\n' + prepared.replace(/^\uFEFF/, "");
}

const __WORKER_EXPORT__ = {
	async scheduled(event, env, ctx) {
		try {
			if (!env.DB) return;
			try {
				await DbService.ensureSchema(env.DB);
			} catch (e) {}
			ctx.waitUntil(
				tgSendDailyReport(env).catch(() => {})
			);
		} catch (e) {}
	},
	async fetch(request, env, ctx) {
		if (!env.DB) {
			return new Response("Database binding 'DB' is missing in Cloudflare Workers settings.", { status: 500 });
		}

		try {
			try {
				await DbService.ensureSchema(env.DB);
			} catch (e) {}
			try {
				trackRequest(env, ctx);
			} catch (e) {}
			if (schemaEnsured) {
				try {
					ctx.waitUntil(checkAutoResets(env, ctx).catch(() => {}));
					ctx.waitUntil(checkAutoRotates(env, ctx).catch(() => {}));
				} catch (e) {}
			}
			const url = new URL(request.url);
			if (Router.isWebSocketUpgrade(request)) {
				return await Router.handleWebSocket(request, env, ctx);
			}
			if (Router.isSubscriptionPath(url.pathname)) {
				return await Router.handleSubscription(url, env, request);
			}
			if (url.pathname === "/telegram" || url.pathname === "/api/telegram") {
				return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "Content-Type": "application/json" } });
			}
			if (url.pathname.startsWith("/api/")) {
				return await Router.handleApi(request, url, env, ctx);
			}
			if (url.pathname === "/app" || url.pathname === "/login") {
				return await Router.handlePanel(request, env);
			}
			if (url.pathname.startsWith("/profile/")) {
				return await Router.handleUserStatus(url, env);
			}
			let rootTheme = "default";
			try {
				const themeRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'panel_theme'").first();
				if (themeRow && themeRow.value) rootTheme = themeRow.value;
			} catch (e) {}
			if (!["default","ocean","sunny","candy"].includes(rootTheme)) rootTheme = "default";
			return new Response(HTML_TEMPLATES.nginx.replace("<html", `<html data-theme="${rootTheme}"`), {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		} catch (err) {
			const msg = (err && err.message) ? err.message : String(err);
			const stack = (err && err.stack) ? String(err.stack).slice(0, 800) : "";
			return new Response("ERR: " + msg + (stack ? ("\n" + stack) : ""), {
				status: 500,
				headers: { "Content-Type": "text/plain; charset=utf-8" },
			});
		}
	},
};
const Router = {
	isWebSocketUpgrade(request) {
		const upgradeHeader = (request.headers.get("Upgrade") || "").toLowerCase();
		return upgradeHeader === "websocket";
	},
	isSubscriptionPath(pathname) {
		return pathname.startsWith("/export/");
	},
	async handleWebSocket(request, env, ctx) {
		try {
			return await handlevIees(env, null, ctx, request);
		} catch (e) {
			try {
				return new Response("Internal Server Error", { status: 500 });
			} catch (_) {
				return new Response(null, { status: 500 });
			}
		}
	},
	async handleSubscription(url, env, request) {
		const offset = 8; // "/export/".length
		let subUser = safeDecodeURI(url.pathname.slice(offset));
		const host = url.hostname;
		try {
			const user = await env.DB.prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE OR uuid = ?").bind(subUser, subUser).first();
			if (!user || user.connection_type !== atob(String.fromCharCode(100,109,120,108,99,51,77,61))) {
				return new Response("Not Found", { status: 404 });
			}
			try {
				const cur = tbReqCache.get(user.username) || 0;
				tbReqCache.set(user.username, cur + 1);
			} catch (e) {}
			const raw = url.searchParams.get("raw") === "1" || url.searchParams.get("format") === "text";
			const accept = ((request && request.headers.get("Accept")) || "").toLowerCase();
			const ua = ((request && request.headers.get("User-Agent")) || "").toLowerCase();
			// Browser → HTML status page (configs with fragment). Clients / ?raw=1 → plain configs text.
			const isClient = /v2ray|clash|sing-box|shadowrocket|quantumult|surge|stash|nekobox|hiddify|streisand|v2box|fair|loon|pharos|sager|passwall|v2rayn|v2rayng|kitsunebi|surfboard/i.test(ua);
			const wantsHtml = !raw && !isClient && (accept.includes("text/html") || ua.includes("mozilla") || ua.includes("chrome") || ua.includes("safari") || !ua);
			if (wantsHtml) {
				// Same UI as /profile status page — server builds links WITH fragment
				const configLinks = buildAllConfigLinks(user, host) || [];
				const userJson = JSON.stringify({
					config_links: configLinks,
					username: user.username,
					uuid: user.uuid,
					limit_gb: user.limit_gb,
					expiry_days: user.expiry_days,
					used_gb: user.used_gb,
					limit_req: user.limit_req,
					used_req: user.used_req,
					is_active: user.is_active,
					online_count: getActiveIpCount(user.active_ips),
					ip_limit: user.ip_limit,
					created_at: user.created_at,
					tls: user.tls,
					port: user.port,
					ips: user.ips,
					fingerprint: user.fingerprint || "chrome",
					user_proxy_iata: user.user_proxy_iata,
					user_proxy_ip: user.user_proxy_ip,
					user_socks5: user.user_socks5 || "",
					frag_len: user.frag_len || "",
					frag_int: user.frag_int || "",
				});
				const bootScript = "window.statusUser=" + userJson.split("<").join("\u003c") + ";";
				let html = HTML_TEMPLATES.status.replace("/* {{USER_DATA_PLACEHOLDER}} */", bootScript);
				html = html.replace("<html", '<html data-theme="default"');
				return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
			}
			return await SubscriptionService.generateText(user, host);
		} catch (err) {
			return new Response("Error building config: " + err.message, { status: 500 });
		}
	},
	async handlePanel(request, env) {
		try {
			let panelTheme = "default";
			try {
				const themeRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'panel_theme'").first();
				if (themeRow && themeRow.value) panelTheme = themeRow.value;
			} catch (e) {}
			if (!["default","ocean","sunny","candy"].includes(panelTheme)) panelTheme = "default";
			const injectTheme = (html) => html.replace("<html", `<html data-theme="${panelTheme}"`);
			const hasPassword = await DbService.getPanelPassword(env.DB);
			if (!hasPassword) {
				const setupHtml = HTML_TEMPLATES.setup || HTML_TEMPLATES.login;
				return new Response(injectTheme(setupHtml), {
					headers: { "Content-Type": "text/html; charset=utf-8" },
				});
			}
			const authorized = await DbService.verifyApiAuth(request, env);
			if (!authorized) {
				return new Response(injectTheme(HTML_TEMPLATES.login), {
					headers: { "Content-Type": "text/html; charset=utf-8" },
				});
			}
			return new Response(injectTheme(HTML_TEMPLATES.panel), {
				headers: {
					"Content-Type": "text/html; charset=utf-8",
					"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
					Pragma: "no-cache",
					Expires: "0",
				},
			});
		} catch (err) {
			return new Response("Panel Error: " + (err && err.message ? err.message : String(err)), { status: 500 });
		}
	},
	async handleUserStatus(url, env) {
		const username = safeDecodeURI(url.pathname.slice(9));
		if (!username) {
			return new Response("Username is required", { status: 400 });
		}
		try {
			const user = await env.DB.prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE OR uuid = ?").bind(username, username).first();
			if (!user) {
				return new Response("User not found", { status: 404 });
			}
			const host = url.hostname;
			const configLinks = buildAllConfigLinks(user, host) || [];
			const userJson = JSON.stringify({
				config_links: configLinks,
				username: user.username,
				uuid: user.uuid,
				limit_gb: user.limit_gb,
				expiry_days: user.expiry_days,
				used_gb: user.used_gb,
				limit_req: user.limit_req,
				used_req: user.used_req,
				is_active: user.is_active,
				online_count: getActiveIpCount(user.active_ips),
				ip_limit: user.ip_limit,
				created_at: user.created_at,
				tls: user.tls,
				port: user.port,
				ips: user.ips,
				fingerprint: user.fingerprint || "chrome",
				user_proxy_iata: user.user_proxy_iata,
				user_proxy_ip: user.user_proxy_ip,
				user_socks5: user.user_socks5 || "",
				frag_len: user.frag_len || "",
				frag_int: user.frag_int || "",
			});
			let panelTheme = "default";
			try {
				const themeRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'panel_theme'").first();
				if (themeRow && themeRow.value) panelTheme = themeRow.value;
			} catch (e) {}
			if (!["default","ocean","sunny","candy"].includes(panelTheme)) panelTheme = "default";
			const bootScript = "window.statusUser=" + userJson.split("<").join("\u003c") + ";";
			let html = HTML_TEMPLATES.status.replace("/* {{USER_DATA_PLACEHOLDER}} */", bootScript);
			html = html.replace("<html", `<html data-theme="${panelTheme}"`);
			return new Response(html, {
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		} catch (err) {
			return new Response("Error: " + err.message, { status: 500 });
		}
	},
	async handleApi(request, url, env, ctx) {
		const hasPassword = await DbService.getPanelPassword(env.DB);
		if (url.pathname === "/api/setup-password" && request.method === "POST") {
			if (hasPassword) {
				return new Response(JSON.stringify({ error: "Password is already set" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const bodySetup = await readJsonBody(request);
			const cleanPassword = String(bodySetup.password || "").trim();
			const cleanUser = String(bodySetup.username || "admin").trim() || "admin";
			if (!cleanPassword || cleanPassword.length < 4) {
				return new Response(JSON.stringify({ error: "Password must be at least 4 characters" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const hashed = await DbService.sha256(cleanPassword);
			await DbService.setPanelPassword(env.DB, hashed);
			try {
				await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_username', ?)").bind(cleanUser).run();
			} catch (e) {}
			tbLoginAttempts.clear();
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=" + hashed + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
				},
			});
		}
		if (url.pathname === "/api/login" && request.method === "POST") {
			const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
			const now = Date.now();
			if (tbLoginAttempts.size > 256) {
				for (const [ip, rec] of tbLoginAttempts) {
					if (now - rec.lastAttempt > 900000) tbLoginAttempts.delete(ip);
				}
			}
			const attemptRecord = tbLoginAttempts.get(clientIP) || { count: 0, lastAttempt: 0 };
			if (attemptRecord.count >= 9 && now - attemptRecord.lastAttempt < 900000) {
				const remaining = Math.ceil((900000 - (now - attemptRecord.lastAttempt)) / 60000);
				return new Response(JSON.stringify({ error: `Access locked. Try again in ${remaining} minute(s).` }), {
					status: 429,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const body = await readJsonBody(request);
			const cleanUsername = String(body.username || "admin").trim() || "admin";
			const cleanPassword = String(body.password || "").trim();
			if (!cleanPassword) {
				return new Response(JSON.stringify({ error: "Password is required" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			let panelUsername = "admin";
			try {
				const urow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'panel_username'").first();
				if (urow && urow.value) panelUsername = String(urow.value).trim();
			} catch (e) {}
			const usernameOk = cleanUsername.toLowerCase() === String(panelUsername).toLowerCase();
			const hashedInput = await DbService.sha256(cleanPassword);
			const storedHash = await DbService.getPanelPassword(env.DB, true);
			let passwordOk = false;
			if (storedHash && storedHash === hashedInput) {
				passwordOk = true;
			} else if (storedHash) {
				const oldHashedInput = await DbService.oldSha256(cleanPassword);
				if (storedHash === oldHashedInput) {
					passwordOk = true;
					await DbService.setPanelPassword(env.DB, hashedInput);
				}
			}
			if (usernameOk && passwordOk) {
				tbLoginAttempts.delete(clientIP);
				return new Response(JSON.stringify({ success: true }), {
					headers: {
						"Content-Type": "application/json; charset=utf-8",
						"Set-Cookie": "panel_session=" + hashedInput + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
					},
				});
			} else {
				attemptRecord.count = now - attemptRecord.lastAttempt > 900000 ? 1 : attemptRecord.count + 1;
				attemptRecord.lastAttempt = now;
				tbLoginAttempts.set(clientIP, attemptRecord);
				return new Response(JSON.stringify({ error: `Wrong username or password (${9 - attemptRecord.count} attempt(s) left)` }), {
					status: 401,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
		}
		if (url.pathname === "/api/random-proxy" && request.method === "GET") {
			try {
				const authorized = await DbService.verifyApiAuth(request, env);
				if (!authorized) {
					return new Response(JSON.stringify({ error: "Unauthorized" }), {
						status: 401,
						headers: { "Content-Type": "application/json; charset=utf-8" },
					});
				}
				const now = Date.now();
				const RESET_MS = 10 * 60 * 1000; // every 10 minutes restart from top
				const SRC = "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text&timeout=3000";

				if (!_tbProxyCursor.list.length || now - (_tbProxyCursor.fetchedAt || 0) > RESET_MS) {
					const res = await fetch(SRC + "&_=" + now, {
						headers: {
							Accept: "text/plain,*/*",
							"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
						},
					});
					if (!res.ok) {
						return new Response(JSON.stringify({ error: "Proxy source error", status: res.status }), {
							status: 502,
							headers: { "Content-Type": "application/json; charset=utf-8" },
						});
					}
					const text = await res.text();
					const lines = String(text || "").split(/\r?\n/).map(function (l) { return l.trim(); }).filter(Boolean);
					const candidates = [];
					const seen = new Set();
					for (let i = 0; i < lines.length; i++) {
						const line = lines[i];
						if (!line || line.charAt(0) === "#") continue;
						let protocol = "socks5";
						let hostport = line;
						const m = line.match(/^(socks5|socks4|socks|http|https):\/\/(.+)$/i);
						if (m) {
							protocol = m[1].toLowerCase() === "socks" ? "socks5" : m[1].toLowerCase();
							hostport = m[2];
						}
						if (protocol !== "socks5" && protocol !== "socks4") continue;
						if (!hostport || hostport.indexOf(":") < 0) continue;
						const proxy = protocol + "://" + hostport;
						if (seen.has(proxy)) continue;
						seen.add(proxy);
						candidates.push({ proxy: proxy, country: "" });
						if (candidates.length >= 400) break;
					}
					if (!candidates.length) {
						return new Response(JSON.stringify({ error: "Empty proxy list" }), {
							status: 404,
							headers: { "Content-Type": "application/json; charset=utf-8" },
						});
					}
					_tbProxyCursor = { list: candidates, at: 0, fetchedAt: now };
				}

				const list = _tbProxyCursor.list;
				const n = list.length;
				if (!n) {
					return new Response(JSON.stringify({ error: "Empty proxy list" }), {
						status: 404,
						headers: { "Content-Type": "application/json; charset=utf-8" },
					});
				}

				// ONE click = ONE proxy (cursor advances every time)
				const idx = _tbProxyCursor.at % n;
				const current = list[idx];
				_tbProxyCursor.at = (idx + 1) % n;

				let pHost = "";
				let pPort = 1080;
				try {
					let remain = String(current.proxy || "").replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
					if (remain.includes("@")) remain = remain.substring(remain.lastIndexOf("@") + 1);
					if (remain.startsWith("[")) {
						const br = remain.indexOf("]");
						pHost = remain.substring(1, br);
						pPort = parseInt(remain.substring(br + 2), 10) || 1080;
					} else {
						const lc = remain.lastIndexOf(":");
						if (lc > 0) {
							pHost = remain.substring(0, lc);
							pPort = parseInt(remain.substring(lc + 1), 10) || 1080;
						} else {
							pHost = remain;
						}
					}
				} catch (eP) {}

				const t0 = Date.now();
				let live = false;
				if (pHost) {
					try {
						live = await testProxyTcpOpen(pHost, pPort, 2200);
					} catch (eT) {
						live = false;
					}
				}
				const ms = Math.max(1, Date.now() - t0);

				let country = current.country || "";
				if (!country && pHost) {
					try {
						country = (await lookupExitCountry(pHost)) || "";
						current.country = country;
					} catch (eC) {}
				}

				if (!live) {
					return new Response(JSON.stringify({
						ok: false,
						error: "Proxy offline — click Random again for next",
						proxy: current.proxy,
						ms: ms,
						country: country || "",
						index: idx,
						next: _tbProxyCursor.at,
						live: false
					}), {
						status: 200,
						headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
					});
				}

				return new Response(JSON.stringify({
					ok: true,
					proxy: current.proxy,
					ms: ms,
					country: country || "",
					source: "proxyscrape",
					live: true,
					verified: true,
					index: idx,
					next: _tbProxyCursor.at
				}), {
					headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
				});
			} catch (e) {
				return new Response(JSON.stringify({ error: "Random failed", detail: String(e && e.message || e) }), {
					status: 500,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
		}

		if (url.pathname === "/api/clean-ips" && request.method === "GET") {
			try {
				const authorized = await DbService.verifyApiAuth(request, env);
				if (!authorized) {
					return new Response(JSON.stringify({ error: "Unauthorized" }), {
						status: 401,
						headers: { "Content-Type": "application/json; charset=utf-8" },
					});
				}
				const operator = (url.searchParams.get("operator") || "all").trim();
				const count = Math.min(100, Math.max(1, parseInt(url.searchParams.get("count") || "20", 10) || 20));
				const data = await fetchCleanIpData();
				const counts = {};
				let totalAll = 0;
				if (data && typeof data === "object") {
					Object.keys(data).forEach((k) => {
						if (Array.isArray(data[k])) {
							counts[k] = data[k].length;
							if (String(k).toLowerCase() !== "all") totalAll += data[k].length;
						}
					});
				}
				counts.all = totalAll;
				const ips = pickCleanIps(data || {}, operator, count);
				return new Response(JSON.stringify({ ips: ips || [], operator, count: (ips || []).length, operators: counts, source: "github" }), {
					headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
				});
			} catch (e) {
				return new Response(JSON.stringify({ error: "CleanIP failed", detail: String((e && e.message) || e) }), {
					status: 500,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
		}

		if (url.pathname === "/api/logout" && request.method === "POST") {
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax",
				},
			});
		}
		if (url.pathname === "/api/recover" && request.method === "POST") {
			const bodyRecFull = await readJsonBody(request);
			const api_token = bodyRecFull.api_token;
			if (!api_token) {
				return new Response(JSON.stringify({ error: "Token is required" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			try {
				const cfRes = await fetch("https://api.cloudflare.com/client/v4/user/tokens/verify", {
					headers: { Authorization: "Bearer " + api_token },
				});
				const cfData = await cfRes.json();
				if (!cfRes.ok || !cfData.success) {
					return new Response(JSON.stringify({ error: "Invalid or expired Cloudflare token" }), {
						status: 401,
						headers: { "Content-Type": "application/json; charset=utf-8" },
					});
				}
				const host = url.hostname;
				let isAuthorized = false;
				if (host.endsWith(".workers.dev")) {
					const parts = host.split(".");
					const targetSubdomain = parts[parts.length - 3];
					const accountsRes = await fetch("https://api.cloudflare.com/client/v4/accounts", {
						headers: { Authorization: "Bearer " + api_token },
					});
					const accountsData = await accountsRes.json();
					if (accountsData.success && accountsData.result) {
						for (const acc of accountsData.result) {
							const subRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${acc.id}/workers/subdomain`, {
								headers: { Authorization: "Bearer " + api_token },
							});
							const subData = await subRes.json();
							if (subData.success && subData.result && subData.result.subdomain === targetSubdomain) {
								isAuthorized = true;
								break;
							}
						}
					}
				} else {
					const zonesRes = await fetch("https://api.cloudflare.com/client/v4/zones", {
						headers: { Authorization: "Bearer " + api_token },
					});
					const zonesData = await zonesRes.json();
					if (zonesData.success && zonesData.result) {
						for (const zone of zonesData.result) {
							if (host === zone.name || host.endsWith("." + zone.name)) {
								isAuthorized = true;
								break;
							}
						}
					}
				}
				if (!isAuthorized) {
					return new Response(JSON.stringify({ error: "This token does not appear to be associated with the account that owns this panel. Please use a token from the correct Cloudflare account." }), {
						status: 403,
						headers: { "Content-Type": "application/json; charset=utf-8" },
					});
				}
				const newPass = String(bodyRecFull.new_password || "").trim();
				const newUser = String(bodyRecFull.username || "admin").trim() || "admin";
				if (newPass && newPass.length >= 4) {
					const hashed = await DbService.sha256(newPass);
					await DbService.setPanelPassword(env.DB, hashed);
					try {
						await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_username', ?)").bind(newUser).run();
					} catch (e) {}
				} else {
					await env.DB.prepare("DELETE FROM settings WHERE key = 'panel_password'").run();
					cachedPanelPassword = null;
				}
				tbLoginAttempts.clear();
				return new Response(JSON.stringify({ success: true, password_set: !!(newPass && newPass.length >= 4) }), {
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			} catch (err) {
				return new Response(JSON.stringify({ error: "Cloudflare API connection error" }), {
					status: 500,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
		}
		const authorized = await DbService.verifyApiAuth(request, env);
		if (!authorized && url.pathname !== "/api/test-proxy") {
			return new Response(JSON.stringify({ error: "Unauthorized" }), {
				status: 401,
				headers: { "Content-Type": "application/json; charset=utf-8" },
			});
		}
		if (url.pathname === "/api/auto-update-setup" && request.method === "POST") {
			const body = await readJsonBody(request);
			if (body.action === "check") {
				const dbTokenRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'cf_token'").first();
				const hasToken = !!env.CF_API_TOKEN || !!(dbTokenRow && dbTokenRow.value);
				const autoUpdateRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'auto_update'").first();
				const isAutoUpdateEnabled = autoUpdateRow ? autoUpdateRow.value === "1" : false;
				return new Response(JSON.stringify({ has_token: hasToken, auto_update: isAutoUpdateEnabled }), { headers: { "Content-Type": "application/json" } });
			}
			if (body.action === "enable") {
				const dbTokenRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'cf_token'").first();
				let token = body.token || env.CF_API_TOKEN || (dbTokenRow ? dbTokenRow.value : null);
				if (!token) return new Response(JSON.stringify({ error: "TOKEN_MISSING" }), { status: 400, headers: { "Content-Type": "application/json" } });
				try {
					const cfRes = await fetch("https://api.cloudflare.com/client/v4/user/tokens/verify", {
						headers: { Authorization: "Bearer " + token },
					});
					const cfData = await cfRes.json();
					if (!cfRes.ok || !cfData.success) {
						return new Response(JSON.stringify({ error: "INVALID_TOKEN" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('cf_token', ?)").bind(token).run();
					await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('auto_update', '1')").run();
					return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
				} catch (e) {
					return new Response(JSON.stringify({ error: "Failed to verify token with Cloudflare" }), { status: 500, headers: { "Content-Type": "application/json" } });
				}
			}
			if (body.action === "disable") {
				await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('auto_update', '0')").run();
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/restart-core" && request.method === "POST") {
			try {
				tbTrafficMap.clear();
				tbConnCount.clear();
				tbLastActive.clear();
				tbLastWrite.clear();
				tbWriteLock.clear();
				tbDnsCache.clear();
				tbReqCache.clear();
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (err) {
				return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/update-panel" && request.method === "POST") {
			const body = await request.json().catch(() => ({}));
			const dbTokenRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'cf_token'").first();
			let currentToken = env.CF_API_TOKEN || (dbTokenRow ? dbTokenRow.value : null) || body.cf_token || null;
			let currentAccountId = env.CF_ACCOUNT_ID;
			if (!currentToken) {
				return new Response(JSON.stringify({ error: "Cloudflare token missing. Add CF_API_TOKEN in Worker settings." }), { status: 400, headers: { "Content-Type": "application/json" } });
			}
			try {
				const cfHeaders = {
					Authorization: "Bearer " + currentToken,
					"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
				};
				if (!currentAccountId) {
					const accRes = await fetch("https://api.cloudflare.com/client/v4/accounts", { headers: cfHeaders });
					if (!accRes.ok) throw new Error("Cloudflare token invalid or expired.");
					const accData = await accRes.json().catch(() => ({}));
					if (!accData.success || !accData.result || accData.result.length === 0) throw new Error("Cloudflare token could not list accounts.");
					currentAccountId = accData.result[0].id;
				}
				const githubRes = await fetch("https://raw.githubusercontent.com/icubaby/TrexBridge/refs/heads/main/src/Panel.js?t=" + Date.now(), {
					headers: {
						"User-Agent": "Mozilla/5.0",
						"Cache-Control": "no-cache",
					},
				});
				if (!githubRes.ok) throw new Error("Could not download update from GitHub. Try again later.");
												let newCode = await githubRes.text();
				newCode = String(newCode || "").replace(/^\uFEFF/, "").replace(/\r\n/g, "\n");
				try {
					newCode = buildEncodedWorkerFromSource(newCode);
				} catch (encErr) {
					throw new Error("Update package failed to build. Try again.");
				}
				const scriptName = env.WORKER_NAME || url.hostname.split(".")[0];
				const bindingsRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}/bindings`, {
					headers: cfHeaders,
				});
				if (!bindingsRes.ok) throw new Error("Token cannot read Worker bindings. Check API permissions.");
				const bindingsData = await bindingsRes.json().catch(() => ({}));
				if (!bindingsData.success) throw new Error("Token cannot edit this Worker. Enable Workers Scripts:Edit.");
				const newBindings = [];
				for (const b of bindingsData.result || []) {
					if (b.name === "CF_API_TOKEN" || b.name === "CF_ACCOUNT_ID") continue;
					if (b.type === "d1") {
						newBindings.push({ type: "d1", name: b.name, id: b.database_id || b.id });
					} else if (b.type === "kv_namespace") {
						newBindings.push({ type: "kv_namespace", name: b.name, namespace_id: b.namespace_id || b.id });
					} else if (b.type === "plain_text") {
						newBindings.push({ type: "plain_text", name: b.name, text: b.text || "" });
					} else if (b.type !== "secret_text") {
						newBindings.push(b);
					}
				}
				newBindings.push({ type: "secret_text", name: "CF_API_TOKEN", text: currentToken });
				newBindings.push({ type: "secret_text", name: "CF_ACCOUNT_ID", text: currentAccountId });
				const metadata = {
					main_module: "worker.js",
					compatibility_date: "2026-07-10",
					compatibility_flags: ["nodejs_compat"],
					bindings: newBindings,
				};
				const formData = new FormData();
				formData.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }), "metadata.json");
				formData.append("worker.js", new Blob([newCode], { type: "application/javascript+module" }), "worker.js");
				const deployRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${currentAccountId}/workers/scripts/${scriptName}`, {
					method: "PUT",
					headers: cfHeaders,
					body: formData,
				});
				if (!deployRes.ok) {
					const errText = await deployRes.text().catch(() => "");
					throw new Error("Deploy failed. Check Cloudflare token permissions.");
				}
				const deployData = await deployRes.json().catch(() => ({}));
				if (!deployData.success) {
					const cfError = deployData.errors && deployData.errors.length > 0 ? deployData.errors[0].message : "Failed to apply update.";
					throw new Error(cfError);
				}
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			} catch (err) {
				return new Response(JSON.stringify({ error: err.message }), { status: 400, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/change-password" && request.method === "POST") {
			const { current_password, new_password } = await readJsonBody(request);
			const cleanCurrent = (current_password || "").trim();
			const cleanNew = (new_password || "").trim();
			if (!cleanCurrent || !cleanNew) {
				return new Response(JSON.stringify({ error: "Current and new password are required" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const currentHash = await DbService.sha256(cleanCurrent);
			const oldCurrentHash = await DbService.oldSha256(cleanCurrent);
			const storedHash = await DbService.getPanelPassword(env.DB, true);
			if (storedHash && storedHash !== currentHash && storedHash !== oldCurrentHash) {
				return new Response(JSON.stringify({ error: "Current password is incorrect" }), {
					status: 401,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			if (cleanNew.length < 4) {
				return new Response(JSON.stringify({ error: "New password must be at least 4 characters" }), {
					status: 400,
					headers: { "Content-Type": "application/json; charset=utf-8" },
				});
			}
			const newHash = await DbService.sha256(cleanNew);
			await DbService.setPanelPassword(env.DB, newHash);
			return new Response(JSON.stringify({ success: true }), {
				headers: {
					"Content-Type": "application/json; charset=utf-8",
					"Set-Cookie": "panel_session=" + newHash + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000",
				},
			});
		}
		if (url.pathname === "/api/settings/bulk") {
			if (request.method === "GET") {
				try {
					const { results } = await env.DB.prepare("SELECT * FROM settings").all();
					const settingsObj = {};
					if (results) {
						results.forEach((r) => {
							if (r.key !== "cf_token" && r.key !== "panel_password") settingsObj[r.key] = r.value;
						});
					}
					return new Response(JSON.stringify(settingsObj), { headers: { "Content-Type": "application/json" } });
				} catch (e) {
					return new Response(JSON.stringify({}), { headers: { "Content-Type": "application/json" } });
				}
			}
			if (request.method === "POST") {
				const body = await readJsonBody(request);
				if (body.settings && typeof body.settings === "object") {
					for (const [k, v] of Object.entries(body.settings)) {
						await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(k, String(v)).run();
					}
				}
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/telegram/setup" && request.method === "POST") {
			const body = await readJsonBody(request);
			const token = (body.token || "").trim();
			const adminIds = (body.admin_ids || "").trim();
			const channel = (body.channel || "@TrexBridge").trim();
			if (!token || !adminIds) {
				return new Response(JSON.stringify({ error: "token and admin_ids are required" }), { status: 400, headers: { "Content-Type": "application/json" } });
			}
			await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('tg_bot_token', ?)").bind(token).run();
			await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('tg_admin_id', ?)").bind(adminIds).run();
			await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('tg_channel', ?)").bind(channel).run();
			const webhookUrl = (body.webhook_url || ("https://" + url.hostname + "/telegram")).trim();
			let webhook = { ok: false, description: "" };
			try {
				const wr = await fetch("https://api.telegram.org/bot" + token + "/setWebhook", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ url: webhookUrl, drop_pending_updates: true }),
				});
				webhook = await wr.json();
			} catch (e) {
				webhook = { ok: false, description: String(e.message || e) };
			}
			let me = null;
			try {
				const mr = await fetch("https://api.telegram.org/bot" + token + "/getMe");
				me = await mr.json();
			} catch (e) {}
			return new Response(JSON.stringify({
				success: true,
				webhook_ok: !!webhook.ok,
				webhook_description: webhook.description || "",
				bot: (me && me.ok && me.result) ? { username: me.result.username, name: me.result.first_name } : null,
			}), { headers: { "Content-Type": "application/json" } });
		}
		if (url.pathname === "/api/proxy-ip") {
			if (request.method === "POST") {
				const { proxy_ip, iata, socks5 } = await readJsonBody(request);
				if (proxy_ip) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_ip', ?)").bind(proxy_ip).run();
				if (iata !== undefined) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_location_iata', ?)").bind(iata).run();
				if (socks5 !== undefined) await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('socks5', ?)").bind(socks5).run();
				return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
			}
			if (request.method === "GET") {
				const rowIp = await env.DB.prepare("SELECT value FROM settings WHERE key = 'proxy_ip'").first();
				const rowIata = await env.DB.prepare("SELECT value FROM settings WHERE key = 'proxy_location_iata'").first();
				const rowSocks = await env.DB.prepare("SELECT value FROM settings WHERE key = 'socks5'").first();
				return new Response(
					JSON.stringify({
						proxy_ip: rowIp ? rowIp.value : "",
						iata: rowIata ? rowIata.value : "",
						socks5: rowSocks ? rowSocks.value : "",
					}),
					{ headers: { "Content-Type": "application/json" } },
				);
			}
		}
		if (url.pathname === "/api/test-proxy" && request.method === "POST") {
			const body = await readJsonBody(request);
			const proxy = body && body.proxy ? String(body.proxy).trim() : "";
			if (!proxy) {
				return new Response(JSON.stringify({ error: "Proxy is not set" }), {
					status: 400,
					headers: { "Content-Type": "application/json" },
				});
			}
			try {
				let ip = "";
				let port = 1080;
				if (proxy.includes("t.me/socks") || proxy.includes("tg://socks")) {
					ip = (proxy.match(/server=([^&]+)/) || [])[1] || "";
					port = parseInt((proxy.match(/port=(\d+)/) || [])[1] || "1080", 10) || 1080;
				} else {
					let remain = proxy.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
					if (remain.includes("@")) remain = remain.substring(remain.lastIndexOf("@") + 1);
					if (remain.startsWith("[")) {
						const br = remain.indexOf("]");
						ip = remain.substring(1, br);
						port = parseInt(remain.substring(br + 2), 10) || 1080;
					} else {
						const lc = remain.lastIndexOf(":");
						if (lc > 0) {
							ip = remain.substring(0, lc);
							port = parseInt(remain.substring(lc + 1), 10) || 1080;
						} else {
							ip = remain;
						}
					}
				}
				if (!ip) {
					return new Response(JSON.stringify({ error: "Invalid proxy format" }), {
						status: 400,
						headers: { "Content-Type": "application/json" },
					});
				}

				// Ping only (TCP)
				const t0 = Date.now();
				let live = false;
				try {
					live = await testProxyTcpOpen(ip, port, 3000);
				} catch (ePing) {
					live = false;
				}
				const ping = Math.max(1, Date.now() - t0);

				if (!live) {
					return new Response(JSON.stringify({
						ok: false,
						success: false,
						error: "Proxy offline (no TCP response)",
						ping: ping,
						ms: ping,
						country: "",
						countryName: "",
						loc: ""
					}), {
						status: 200,
						headers: { "Content-Type": "application/json" },
					});
				}

				// Location
				let country = "";
				let countryName = "";
				try {
					const geoRes = await fetch("http://ip-api.com/json/" + encodeURIComponent(ip) + "?fields=status,country,countryCode", {
						headers: { Accept: "application/json" },
					});
					if (geoRes.ok) {
						const geo = await geoRes.json();
						if (geo && geo.status === "success") {
							country = String(geo.countryCode || "").toUpperCase();
							countryName = String(geo.country || "");
						}
					}
				} catch (eGeo) {}
				if (!country) {
					try {
						country = (await lookupExitCountry(ip)) || "";
					} catch (e2) {}
				}

				const loc = countryName ? (country + " · " + countryName) : (country || "");
				return new Response(JSON.stringify({
					ok: true,
					success: true,
					ping: ping,
					ms: ping,
					country: country,
					countryName: countryName,
					loc: loc,
					ip: ip,
					port: port
				}), {
					headers: { "Content-Type": "application/json" },
				});
			} catch (e) {
				let msg = String(e && e.message || e || "error");
				if (msg.includes("Stream was cancelled") || msg.includes("network")) msg = "Connection lost (proxy offline)";
				else if (/timeout|timed out/i.test(msg)) msg = "Connection timeout";
				else if (/Invalid URL|Invalid format/i.test(msg)) msg = "Invalid proxy format";
				return new Response(JSON.stringify({ error: msg, ok: false }), {
					status: 500,
					headers: { "Content-Type": "application/json" },
				});
			}
		}

		if (url.pathname === "/api/exit-countries" && request.method === "GET") {
			try {
				const countries = await buildExitCountries();
				return new Response(JSON.stringify({ ok: true, countries }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
			} catch (e) {
				return new Response(JSON.stringify({ ok: false, error: e.message || String(e), countries: [] }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/exit-proxies" && request.method === "GET") {
			try {
				const cc = (url.searchParams.get("cc") || "").trim().toUpperCase();
				if (!cc) return new Response(JSON.stringify({ ok: false, error: "cc required" }), { status: 400, headers: { "Content-Type": "application/json" } });
				const force = url.searchParams.get("force") === "1";
				const proxies = await buildExitProxiesForCountry(cc, 36, 12, force);
				const cached = _exitPingCache[cc];
				const cachedAge = cached ? Date.now() - cached.at : null;
				return new Response(JSON.stringify({
					ok: true,
					cc,
					name: cc,
					proxies,
					cached: !force && cachedAge != null && cachedAge < EXIT_PING_CACHE_MS,
					cacheTtlMs: EXIT_PING_CACHE_MS,
					cachedAgeMs: cachedAge,
				}), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
			} catch (e) {
				return new Response(JSON.stringify({ ok: false, error: e.message || String(e), proxies: [] }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname === "/api/exit-random" && request.method === "GET") {
			try {
				const item = await pickRandomExitProxy(8);
				if (!item) return new Response(JSON.stringify({ ok: false, error: "No proxy available from Proxifly — try again" }), { status: 404, headers: { "Content-Type": "application/json" } });
				return new Response(JSON.stringify({ ok: true, proxy: item }), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
			} catch (e) {
				return new Response(JSON.stringify({ ok: false, error: e.message || String(e) }), { status: 500, headers: { "Content-Type": "application/json" } });
			}
		}
		if (url.pathname.startsWith("/api/users")) {
			const pathParts = url.pathname.split("/").filter(Boolean);
			if (pathParts.length >= 4 && pathParts[pathParts.length - 1] === "configs" && request.method === "GET") {
				const username = safeDecodeURI(pathParts[pathParts.length - 2] || "");
				const user = await env.DB.prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE").bind(username).first();
				if (!user) {
					return new Response(JSON.stringify({ error: "User not found" }), { status: 404, headers: { "Content-Type": "application/json" } });
				}
				const host = url.hostname;
				const links = buildAllConfigLinks(user, host);
				return new Response(JSON.stringify({ links, count: links.length, trex: isTrexFrag(user), frag_len: user.frag_len || "" }), {
					headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
				});
			}
			const isUserAction = pathParts.length > 2;
			if (isUserAction) {
				const username = safeDecodeURI(pathParts[pathParts.length - 1]);
				if (request.method === "PUT") {
					const body = await readJsonBody(request);
					if (Object.keys(body).length === 0) {
						return new Response(JSON.stringify({ error: "Invalid request body" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					if (body.toggle_only !== undefined) {
						await env.DB.prepare("UPDATE users SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE username = ?").bind(username).run();
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					} else if (body.reset_action !== undefined) {
						if (body.reset_action === "volume") {
							await env.DB.prepare("UPDATE users SET used_gb = 0, is_active = 1 WHERE username = ?").bind(username).run();
							tbTrafficMap.set(username, 0);
						} else if (body.reset_action === "req") {
							await env.DB.prepare("UPDATE users SET used_req = 0, is_active = 1 WHERE username = ?").bind(username).run();
							tbReqCache.set(username, 0);
						} else if (body.reset_action === "time") {
							await env.DB.prepare("UPDATE users SET created_at = CURRENT_TIMESTAMP, is_active = 1 WHERE username = ?").bind(username).run();
						}
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					} else {
						const { username: new_username, limit_gb, expiry_days, limit_req, ips, tls, port, fingerprint, ip_limit, block_porn, block_ads, frag_len, frag_int, user_proxy_iata, user_socks5, user_proxy_ip, auto_reset_vol_days, auto_reset_req_days, auto_rotate_ip, rotate_time, ip_operator, ip_count, auto_rotate_user_proxy } = body;
						if (new_username && new_username !== username) {
							if (!/^[a-zA-Z0-9_-]+$/.test(new_username)) {
								return new Response(JSON.stringify({ error: "New username is invalid" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
							}
							const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE").bind(new_username).first();
							if (existing) {
								return new Response(JSON.stringify({ error: "Username already exists" }), { status: 400, headers: { "Content-Type": "application/json" } });
							}
							if (tbTrafficMap.has(username)) {
								tbTrafficMap.set(new_username, tbTrafficMap.get(username));
								tbTrafficMap.delete(username);
							}
							if (tbReqCache.has(username)) {
								tbReqCache.set(new_username, tbReqCache.get(username));
								tbReqCache.delete(username);
							}
							if (tbConnCount.has(username)) {
								tbConnCount.set(new_username, tbConnCount.get(username));
								tbConnCount.delete(username);
							}
							if (tbLastActive.has(username)) {
								tbLastActive.set(new_username, tbLastActive.get(username));
								tbLastActive.delete(username);
							}
						}
						await env.DB.prepare("UPDATE users SET username = ?, limit_gb = ?, expiry_days = ?, limit_req = ?, ips = ?, tls = ?, port = ?, fingerprint = ?, max_connections = ?, ip_limit = ?, block_porn = ?, block_ads = ?, frag_len = ?, frag_int = ?, user_proxy_iata = ?, user_socks5 = ?, user_proxy_ip = ?, auto_reset_vol_days = ?, auto_reset_req_days = ?, auto_rotate_ip = ?, rotate_time = ?, ip_operator = ?, ip_count = ?, auto_rotate_user_proxy = ? WHERE username = ?")
							.bind(new_username || username, limit_gb ? parseFloat(limit_gb) : null, expiry_days ? parseInt(expiry_days) : null, limit_req ? parseInt(limit_req) : null, ips || null, tls, port, fingerprint || "chrome", ip_limit ? parseInt(ip_limit) : null, ip_limit ? parseInt(ip_limit) : null, block_porn ? 1 : 0, block_ads ? 1 : 0, frag_len !== undefined && frag_len !== null && frag_len !== "" ? frag_len : JSON.stringify({mode:"default",packets:"tlshello",length:"100-200",interval:"1-1",maxSplit:"100-200",protocols:"vless"}), frag_int !== undefined && frag_int !== null && frag_int !== "" ? frag_int : "1-1", user_proxy_iata || null, user_socks5 || null, user_proxy_ip || null, auto_reset_vol_days ? parseInt(auto_reset_vol_days) : 0, auto_reset_req_days ? parseInt(auto_reset_req_days) : 0, auto_rotate_ip || 0, rotate_time || 0, ip_operator || "all", ip_count || 20, auto_rotate_user_proxy ? 1 : 0, username)
							.run();
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					}
				}
				if (request.method === "DELETE") {
					await env.DB.prepare("DELETE FROM users WHERE username = ?").bind(username).run();
					return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
				}
			} else {
				if (request.method === "GET") {
					try {
						await flushExpiredTraffic(env);
					} catch (e) {}
					try {
						const { results } = await env.DB.prepare("SELECT * FROM users ORDER BY id DESC").all();
						const now = Date.now();
						const enrichedUsers = (results || []).map((user) => {
							const uname = user.username;
							const memBytes = tbTrafficMap.get(uname) || 0;
							const memGb = memBytes / (1024 * 1024 * 1024);
							const memReqs = tbReqCache.get(uname) || 0;
							const connN = tbConnCount.get(uname) || 0;
							const ipOnline = getActiveIpCount(user.active_ips);
							const onlineN = Math.max(ipOnline, connN);
							const lastAct = Math.max(Number(user.last_active) || 0, tbLastActive.get(uname) || 0);
							const isOn = onlineN > 0 || (lastAct && now - lastAct < 60000) ? 1 : 0;
							return {
								...user,
								used_gb: (parseFloat(user.used_gb) || 0) + memGb,
								used_req: (parseInt(user.used_req, 10) || 0) + memReqs,
								last_active: lastAct || user.last_active,
								is_online: isOn,
								online_count: onlineN || (isOn ? 1 : 0),
							};
						});
						let cfReqs = { today: 0, total: 0, limit: 100000 };
						try {
							const cachedToday = (CF_REQ_CACHE.base || 0) + (CF_REQ_CACHE.delta || 0);
							if (cachedToday > 0) {
								cfReqs.today = cachedToday;
								cfReqs.total = cachedToday;
								cfReqs.limit = 100000;
							} else {
								const todayStr = new Date().toISOString().split("T")[0];
								const dateRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_last_date'").first();
								const totalRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_total'").first();
								let dbTotal = totalRow ? parseInt(totalRow.value) || 0 : 0;
								let dbToday = 0;
								if (dateRow && dateRow.value === todayStr) {
									const todayRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_today'").first();
									dbToday = todayRow ? parseInt(todayRow.value) || 0 : 0;
								}
								cfReqs.today = dbToday + tbReqTotal;
								cfReqs.total = dbTotal + tbReqTotal;
							}
							const CACHE_MS = 45000;
							const needsRefresh = !CF_REQ_CACHE.fetchedAt || Date.now() - CF_REQ_CACHE.fetchedAt >= CACHE_MS;
							if (needsRefresh && ctx) {
								ctx.waitUntil(fetchCfAccountRequestsToday(env).catch(() => {}));
							}
						} catch (e) {}
						return new Response(
							JSON.stringify({
								users: enrichedUsers,
								serverTime: now,
								cfRequestsToday: cfReqs.today,
								cfRequestsTotal: cfReqs.total,
								cfRequestsLimit: cfReqs.limit || 100000,
							}),
							{
								headers: {
									"Content-Type": "application/json",
									"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
								},
							},
						);
					} catch (dbErr) {
						return new Response(
							JSON.stringify({
								users: [],
								serverTime: Date.now(),
								cfRequestsToday: 0,
								cfRequestsTotal: 0,
								error: dbErr.message,
							}),
							{
								status: 200,
								headers: {
									"Content-Type": "application/json",
									"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
								},
							},
						);
					}
				}
				if (request.method === "POST") {
					const { username, uuid, limit_gb, expiry_days, limit_req, ips, tls, port, fingerprint, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int, user_proxy_iata, user_socks5, user_proxy_ip, auto_reset_vol_days, auto_reset_req_days, auto_rotate_ip, rotate_time, ip_operator, ip_count, auto_rotate_user_proxy } = await readJsonBody(request);
					if (!username) {
						return new Response(JSON.stringify({ error: "Username is required" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					if (username.length > 48) {
						return new Response(JSON.stringify({ error: "Username cannot be longer than 48 characters" }), { status: 400, headers: { "Content-Type": "application/json" } });
					}
					if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
						return new Response(JSON.stringify({ error: "Invalid username (letters, numbers, dash and underscore only)" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
					}
					let finalUuid = uuid;
					if (!finalUuid) {
						try {
							if (typeof crypto !== "undefined" && crypto.randomUUID) finalUuid = crypto.randomUUID();
						} catch (eU) {}
						if (!finalUuid) {
							const randomHex = Array.from(crypto.getRandomValues(new Uint8Array(16)))
								.map((b) => b.toString(16).padStart(2, "0"))
								.join("");
							finalUuid = randomHex.slice(0, 8) + "-" + randomHex.slice(8, 12) + "-" + randomHex.slice(12, 16) + "-" + randomHex.slice(16, 20) + "-" + randomHex.slice(20, 32);
						}
					}
					const parsedUsedGb = parseFloat(used_gb);
					const finalUsedGb = !isNaN(parsedUsedGb) ? parsedUsedGb : 0;
					const parsedUsedReq = parseInt(used_req);
					const finalUsedReq = !isNaN(parsedUsedReq) ? parsedUsedReq : 0;
					const finalCreatedAt = created_at || new Date().toISOString();
					const parsedIsActive = parseInt(is_active);
					const finalIsActive = !isNaN(parsedIsActive) ? parsedIsActive : 1;
					const existingUser = await env.DB.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE").bind(username).first();
					if (existingUser) {
						return new Response(JSON.stringify({ error: "Username already exists" }), { status: 400, headers: { "Content-Type": "application/json; charset=utf-8" } });
					}
					try {
						const todayUtc = Math.floor(Date.now() / 86400000) * 86400000;
						const nowTime = Date.now();
						await env.DB.prepare("INSERT INTO users (username, uuid, limit_gb, expiry_days, limit_req, ips, connection_type, tls, port, fingerprint, max_connections, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int, user_proxy_iata, user_socks5, user_proxy_ip, auto_reset_vol_days, auto_reset_req_days, last_reset_vol_time, last_reset_req_time, auto_rotate_ip, rotate_time, ip_operator, ip_count, last_rotate_time, auto_rotate_user_proxy) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
							.bind(username, finalUuid, limit_gb ? parseFloat(limit_gb) : null, expiry_days ? parseInt(expiry_days) : null, limit_req ? parseInt(limit_req) : null, ips || null, atob(String.fromCharCode(100,109,120,108,99,51,77,61)), tls, port, fingerprint || "chrome", ip_limit ? parseInt(ip_limit) : null, ip_limit ? parseInt(ip_limit) : null, finalUsedGb, finalUsedReq, finalCreatedAt, finalIsActive, block_porn ? 1 : 0, block_ads ? 1 : 0, (frag_len !== undefined && frag_len !== null && String(frag_len).trim() !== "") ? (typeof frag_len === "object" ? JSON.stringify(frag_len) : String(frag_len)) : TREX_FRAG_JSON, frag_int !== undefined && frag_int !== null ? String(frag_int) : "", user_proxy_iata || null, user_socks5 || null, user_proxy_ip || null, auto_reset_vol_days ? parseInt(auto_reset_vol_days) : 0, auto_reset_req_days ? parseInt(auto_reset_req_days) : 0, todayUtc, todayUtc, auto_rotate_ip || 0, rotate_time || 0, ip_operator || "all", ip_count || 20, nowTime, auto_rotate_user_proxy ? 1 : 0)
							.run();
						return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
					} catch (err) {
						return new Response(JSON.stringify({ error: "Create failed: " + String(err && err.message || err) }), { status: 500, headers: { "Content-Type": "application/json" } });
					}
				}
			}
		}
		return new Response(JSON.stringify({ error: "Not Found" }), { status: 404, headers: { "Content-Type": "application/json" } });
	},
};
let schemaEnsured = false;
let schemaPromise = null;
let cachedPanelPassword = null;
const DbService = {
	async ensureSchema(db) {
		if (schemaEnsured) return;
		if (schemaPromise) {
			await schemaPromise;
			return;
		}
		schemaPromise = (async () => {
			try {
				await db.prepare(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, uuid TEXT, limit_gb REAL, expiry_days INTEGER, ips TEXT, connection_type TEXT, tls TEXT, port INTEGER, used_gb REAL DEFAULT 0, is_active INTEGER DEFAULT 1, last_active INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`).run();
			} catch (e) {}
			try {
				await db.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)").run();
			} catch (e) {}
			try {
				const { results } = await db.prepare("PRAGMA table_info(users)").all();
				const existingCols = new Set((results || []).map((r) => r.name));
				const colsToAdd = [
					{ name: "is_active", def: "INTEGER DEFAULT 1" },
					{ name: "last_active", def: "INTEGER" },
					{ name: "fingerprint", def: "TEXT DEFAULT 'chrome'" },
					{ name: "max_connections", def: "INTEGER" },
					{ name: "limit_req", def: "INTEGER" },
					{ name: "used_req", def: "INTEGER DEFAULT 0" },
					{ name: "ip_limit", def: "INTEGER DEFAULT NULL" },
					{ name: "active_ips", def: "TEXT DEFAULT NULL" },
					{ name: "block_porn", def: "INTEGER DEFAULT 0" },
					{ name: "block_ads", def: "INTEGER DEFAULT 0" },
					{ name: "frag_len", def: "TEXT DEFAULT '200-3000'" },
					{ name: "frag_int", def: "TEXT DEFAULT '1-2'" },
					{ name: "lifetime_used_gb", def: "REAL DEFAULT 0" },
					{ name: "user_proxy_ip", def: "TEXT DEFAULT NULL" },
					{ name: "user_proxy_iata", def: "TEXT DEFAULT NULL" },
					{ name: "user_socks5", def: "TEXT DEFAULT NULL" },
					{ name: "auto_reset_vol_days", def: "INTEGER DEFAULT 0" },
					{ name: "auto_reset_req_days", def: "INTEGER DEFAULT 0" },
					{ name: "last_reset_vol_time", def: "INTEGER DEFAULT 0" },
					{ name: "last_reset_req_time", def: "INTEGER DEFAULT 0" },
					{ name: "auto_rotate_ip", def: "INTEGER DEFAULT 0" },
					{ name: "rotate_time", def: "INTEGER DEFAULT 0" },
					{ name: "ip_operator", def: "TEXT DEFAULT 'all'" },
					{ name: "ip_count", def: "INTEGER DEFAULT 20" },
					{ name: "last_rotate_time", def: "INTEGER DEFAULT 0" },
					{ name: "auto_rotate_user_proxy", def: "INTEGER DEFAULT 0" },
				];
				const stmts = [];
				for (const col of colsToAdd) {
					if (!existingCols.has(col.name)) {
						stmts.push(db.prepare(`ALTER TABLE users ADD COLUMN ${col.name} ${col.def}`));
					}
				}
				if (stmts.length > 0) {
					await db.batch(stmts);
				}
			} catch (e) {}
			try {
				await db.prepare("UPDATE users SET ip_limit = max_connections WHERE ip_limit IS NULL AND max_connections IS NOT NULL").run();
			} catch (e) {}
			try {
				await db.prepare("UPDATE users SET lifetime_used_gb = used_gb WHERE lifetime_used_gb = 0 OR lifetime_used_gb IS NULL").run();
			} catch (e) {}
		})();
		await schemaPromise;
		schemaEnsured = true;
	},
	async getPanelPassword(db, forceRefresh = true) {
		try {
			const row = await db.prepare("SELECT value FROM settings WHERE key = 'panel_password'").first();
			cachedPanelPassword = row && row.value ? row.value : null;
			return cachedPanelPassword;
		} catch (e) {
			return null;
		}
	},
	async setPanelPassword(db, password) {
		await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_password', ?)").bind(password).run();
		cachedPanelPassword = password;
	},
	async verifyApiAuth(request, env) {
		const storedPasswordHash = await this.getPanelPassword(env.DB);
		if (!storedPasswordHash) return true;
		const cookies = request.headers.get("Cookie") || "";
		const sessionCookie = cookies.split(";").map((c) => c.trim()).find((c) => c.startsWith("panel_session="));
		if (!sessionCookie) return false;
		let sessionToken = sessionCookie.slice("panel_session=".length).trim();
		try { sessionToken = decodeURIComponent(sessionToken); } catch (e) {}
		if (sessionToken && sessionToken === storedPasswordHash) return true;
		return false;
	},
	async sha256(message) {
		const msgBuffer = new TextEncoder().encode(message);
		const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
	},
	async oldSha256(message) {
		return this.sha256(message);
	},
};
function getActiveIpCount(activeIpsJson) {
	if (!activeIpsJson) return 0;
	try {
		const activeIps = JSON.parse(activeIpsJson);
		const now = Date.now();
		let count = 0;
		for (const [ip, data] of Object.entries(activeIps)) {
			const lastSeen = data && typeof data === "object" ? data.timestamp : data;
			if (now - lastSeen <= 60000) {
				count++;
			}
		}
		return count;
	} catch (e) {
		return 0;
	}
}
const SubscriptionService = {
	async generateText(user, host) {
		const links = buildAllConfigLinks(user, host) || [];
		const NL = String.fromCharCode(10);
		const noise = [
			"# System Update Feed: OK",
			"# Sync Code: " + Math.random().toString(36).slice(2, 10),
			"# Version: 2.10.1",
			"# Description: Secure Node Configurations",
			""
		].join(NL);
		const plainContent = noise + links.join(NL);
		const downloadBytes = Math.floor((user.used_gb || 0) * 1073741824);
		const totalBytes = user.limit_gb ? Math.floor(user.limit_gb * 1073741824) : 0;
		let expireTimestamp = 0;
		if (user.expiry_days && user.created_at) {
			expireTimestamp = Math.floor((new Date(user.created_at).getTime() + user.expiry_days * 86400000) / 1000);
		}
		const subUserInfo = "upload=0; download=" + downloadBytes + "; total=" + totalBytes + "; expire=" + expireTimestamp;
		return new Response(plainContent, {
			headers: {
				"Content-Type": "text/plain; charset=utf-8",
				"Access-Control-Allow-Origin": "*",
				"Cache-Control": "no-store",
				"Subscription-Userinfo": subUserInfo,
			},
		});
	},
	async generateHtml(user, host) {
		const links = buildAllConfigLinks(user, host) || [];
		const used = Number(user.used_gb) || 0;
		const limit = user.limit_gb != null && user.limit_gb !== "" ? Number(user.limit_gb) : null;
		const usedLabel = used < 1 ? (used * 1024).toFixed(0) + " Mb" : used.toFixed(2) + " Gb";
		const limitLabel = limit == null || isNaN(limit) ? "∞" : limit < 1 ? (limit * 1024).toFixed(0) + " Mb" : limit.toFixed(2) + " Gb";
		const rem = limit != null && !isNaN(limit) ? Math.max(0, limit - used) : null;
		const remLabel = rem == null ? "∞" : rem < 1 ? (rem * 1024).toFixed(0) + " Mb" : rem.toFixed(2) + " Gb";
		let pct = 0;
		if (limit != null && limit > 0) pct = Math.min(100, (used / limit) * 100);
		const statusUrl = "https://" + host + "/profile/" + encodeURIComponent(user.username);
		const subUrl = "https://" + host + "/export/" + encodeURIComponent(user.username);
		const esc = (t) => String(t == null ? "" : t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
		const linksJson = JSON.stringify(links);
		const active = user.is_active !== 0 && user.is_active !== "0";
		const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no"/>
<title>TrexBridge · subscription · v3</title>
<style>
:root{--bg:#f5f0e8;--card:#fffdf5;--ink:#0a0a0a;--muted:#71717a;--green:#22c55e;--lime:#bef264;--yellow:#facc15;--sky:#7dd3fc;--red:#ef4444}
*{box-sizing:border-box;margin:0;padding:0;border-radius:0!important}
body{font-family:system-ui,sans-serif;font-weight:700;background:var(--bg);color:var(--ink);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px 12px}
.grid-bg{position:fixed;inset:-20px;z-index:0;pointer-events:none;background-color:#f5f0e8;background-image:linear-gradient(to right,rgba(0,0,0,.11) 1.5px,transparent 1.5px),linear-gradient(to bottom,rgba(0,0,0,.11) 1.5px,transparent 1.5px);background-size:40px 40px}
.card{position:relative;z-index:1;width:100%;max-width:540px;background:var(--card);border:3.5px solid #000;box-shadow:6px 6px 0 #000;padding:1.25rem 1.1rem}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.15rem;gap:12px}
.brand{display:flex;align-items:center;font-size:1.35rem;font-weight:900;letter-spacing:-.5px}
.brand-box{position:relative;overflow:hidden;background:var(--green);padding:3px 10px;border:2.5px solid #000;box-shadow:3px 3px 0 #000}
.brand-box::after{content:"";position:absolute;top:0;bottom:0;left:-60%;width:40%;background:linear-gradient(90deg,transparent,rgba(255,255,255,.45),transparent);transform:skewX(-18deg);animation:shine 3.8s ease-in-out infinite}
@keyframes shine{0%{left:-60%}100%{left:130%}}
.brand-bridge{padding-left:8px}
.badge{display:inline-flex;align-items:center;gap:7px;padding:.4rem .9rem;border:3px solid #000;background:#fff;box-shadow:3px 3px 0 #000;font-size:.78rem;font-weight:800}
.badge-dot{width:10px;height:10px;background:var(--green);border:2px solid #000}
.badge-dot.off{background:var(--red)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:1rem}
.stat{text-align:center;padding:12px 4px;border:3px solid #000;background:#fff;box-shadow:3px 3px 0 #000}
.stat-label{font-size:.65rem;font-weight:800;color:var(--muted);text-transform:uppercase}
.stat-value{font-size:1.05rem;font-weight:900;margin-top:4px}
.progress-section{margin-bottom:1rem}
.progress-header{display:flex;justify-content:space-between;font-size:.82rem;font-weight:800;margin-bottom:8px}
.progress-bar{height:18px;background:#fff;border:3px solid #000;overflow:hidden}
.progress-fill{height:100%;background:var(--green);border-right:2.5px solid #000;width:0;transition:width .8s cubic-bezier(.34,1.56,.64,1)}
.info-box{display:flex;justify-content:space-between;align-items:center;padding:.75rem 1rem;border:3px solid #000;background:#fff;box-shadow:3px 3px 0 #000;margin-bottom:1rem}
.info-label{font-size:.8rem;font-weight:800;color:var(--muted)}
.info-value{font-size:.95rem;font-weight:900}
.actions{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:1rem}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:.5rem .9rem;border:2.5px solid #000;background:#fff;box-shadow:2.5px 2.5px 0 #000;font:inherit;font-weight:800;font-size:.78rem;cursor:pointer;color:#000;text-decoration:none}
.btn:active{transform:translate(1px,1px);box-shadow:1px 1px 0 #000}
.btn-y{background:#eab308;color:#000}.btn-g{background:#38bdf8;color:#000}.btn-b{background:#7dd3fc;color:#000}.btn-p{background:#c4b5fd;color:#000}
.links-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.links-title{font-size:.88rem;font-weight:900}
.links-list{display:flex;flex-direction:column;gap:8px;max-height:240px;overflow-y:auto;margin-bottom:1rem}
.link-item{display:flex;align-items:center;gap:8px;padding:10px 12px;border:2.5px solid #000;background:#fff;box-shadow:2.5px 2.5px 0 #000}
.link-url{flex:1;min-width:0;font-family:ui-monospace,monospace;font-size:.68rem;font-weight:600;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.copy-btn{flex-shrink:0;padding:6px 12px;border:2.5px solid #000;background:#fff;box-shadow:2px 2px 0 #000;font:inherit;font-weight:800;font-size:.7rem;cursor:pointer}
.copy-btn.ok{background:var(--green)}
.footer{margin-top:.5rem;text-align:center;font-size:.68rem;font-weight:700;color:var(--muted)}
.qr-box{display:none;margin:0 auto 1rem;text-align:center}
.qr-box.show{display:block}
.qr-box img{border:3px solid #000;background:#fff;box-shadow:3px 3px 0 #000}
#toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%) translateY(12px);background:#fff;border:3px solid #000;box-shadow:4px 4px 0 #000;padding:.7rem 1rem;font-weight:800;font-size:.85rem;opacity:0;transition:.2s;pointer-events:none;z-index:99}
#toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
@media(max-width:480px){.stats{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<div class="grid-bg"></div>
<div class="card">
  <div class="header">
    <div class="brand"><span class="brand-box">Trex</span><span class="brand-bridge">Bridge</span></div>
    <span class="badge"><span class="badge-dot ${active ? "" : "off"}"></span>${active ? "Active" : "Inactive"}</span>
  </div>
  <div class="stats">
    <div class="stat"><div class="stat-label">Usage</div><div class="stat-value">${esc(usedLabel)}</div></div>
    <div class="stat"><div class="stat-label">Limit</div><div class="stat-value">${esc(limitLabel)}</div></div>
    <div class="stat"><div class="stat-label">Remain</div><div class="stat-value">${esc(remLabel)}</div></div>
    <div class="stat"><div class="stat-label">Configs</div><div class="stat-value">${links.length}</div></div>
  </div>
  <div class="progress-section">
    <div class="progress-header"><span>Traffic usage</span><span>${limit != null && limit > 0 ? pct.toFixed(0) + "%" : (used > 0 ? "Used" : "0%")}</span></div>
    <div class="progress-bar"><div class="progress-fill" id="pf" style="width:${limit != null && limit > 0 ? Math.max(pct, used > 0 ? 1.5 : 0) : used > 0 ? 8 : 0}%"></div></div>
  </div>
  <div class="info-box"><span class="info-label">User</span><span class="info-value">${esc(user.username)}</span></div>
  <div class="actions">
    <button type="button" class="btn btn-y" id="copyAll" style="background:#eab308;color:#000;font-weight:900;border:2.5px solid #000;box-shadow:3px 3px 0 #000">Copy all</button>
    <button type="button" class="btn btn-g" id="copySub" style="background:#38bdf8;color:#000;font-weight:900;border:2.5px solid #000;box-shadow:3px 3px 0 #000">Copy sub URL</button>
    <button type="button" class="btn btn-p" id="toggleQr" style="background:#c4b5fd;color:#000;font-weight:900;border:2.5px solid #000;box-shadow:3px 3px 0 #000">QR code</button>
  </div>
  <div class="qr-box" id="qrBox">
    <div style="display:inline-block;background:#fef08a;border:3px solid #000;padding:12px;box-shadow:3px 3px 0 #000">
      <img id="qrImg" width="200" height="200" alt="QR" style="display:block;border:2.5px solid #000;background:#fff"/>
    </div>
  </div>
  <div class="links-header"><span class="links-title">Configs</span></div>
  <div class="links-list" id="list"></div>
  <div class="footer">TrexBridge · subscription · v3</div>
</div>
<div id="toast"></div>
<script>
var LINKS=${linksJson};
var SUB=${JSON.stringify(subUrl)};
function toast(t){var e=document.getElementById("toast");e.textContent=t;e.classList.add("show");clearTimeout(window.__tt);window.__tt=setTimeout(function(){e.classList.remove("show")},1800)}
function copy(t,btn){function done(){toast("Copied");if(btn){btn.classList.add("ok");btn.textContent="OK";setTimeout(function(){btn.classList.remove("ok");btn.textContent="Copy"},900)}}
if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(t).then(done).catch(fb);else fb();
function fb(){var a=document.createElement("textarea");a.value=t;document.body.appendChild(a);a.select();try{document.execCommand("copy");done()}catch(e){toast("Copy failed")}document.body.removeChild(a)}}
document.getElementById("copyAll").onclick=function(){if(!LINKS.length)return toast("No configs");copy(LINKS.join(String.fromCharCode(10)))};
document.getElementById("copySub").onclick=function(){copy(SUB)};
document.getElementById("toggleQr").onclick=function(){
  var box=document.getElementById("qrBox");
  var img=document.getElementById("qrImg");
  if(!box.classList.contains("show")){
    img.src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&margin=10&color=0a0a0a&bgcolor=ffffff&data="+encodeURIComponent(SUB);
    box.classList.add("show");
  } else box.classList.remove("show");
};
(function(){
  var list=document.getElementById("list");
  if(!LINKS.length){list.innerHTML='<div class="link-item"><div class="link-url">No configs</div></div>';return}
  list.innerHTML=LINKS.map(function(u,i){
    var short=u.length>70?u.slice(0,66)+"…":u;
    return '<div class="link-item"><div class="link-url">'+short.replace(/</g,"&lt;")+'</div><button type="button" class="copy-btn" data-i="'+i+'">Copy</button></div>';
  }).join("");
  list.querySelectorAll(".copy-btn").forEach(function(btn){
    btn.onclick=function(){var i=+btn.getAttribute("data-i");if(LINKS[i])copy(LINKS[i],btn)};
  });
})();
</script>
</body>
</html>`;
		return new Response(html, {
			headers: {
				"Content-Type": "text/html; charset=utf-8",
				"Cache-Control": "no-store",
			},
		});
	}

};
async function flushExpiredTraffic(env) {
	const now = Date.now();
	for (const [key, val] of tbDnsCache.entries()) {
		if (now > val.expires) tbDnsCache.delete(key);
	}
	for (const [ip, record] of tbLoginAttempts.entries()) {
		if (now - record.lastAttempt > 900000) tbLoginAttempts.delete(ip);
	}
	const allUsers = new Set([...tbTrafficMap.keys(), ...tbReqCache.keys()]);
	for (const uname of allUsers) {
		const cachedBytes = tbTrafficMap.get(uname) || 0;
		const cachedReqs = tbReqCache.get(uname) || 0;
		const activeCount = tbConnCount.get(uname) || 0;
		if (cachedBytes <= 0 && cachedReqs <= 0) {
			tbTrafficMap.delete(uname);
			tbReqCache.delete(uname);
			if (activeCount <= 0) {
				tbLastActive.delete(uname);
				tbLastActive.delete(uname + "_hb");
			}
			continue;
		}
		if (tbWriteLock.get(uname)) continue;
		const lastActive = tbLastActive.get(uname) || 0;
		if (activeCount <= 0 || now - lastActive > 20000) {
			tbWriteLock.set(uname, true);
			tbTrafficMap.set(uname, 0);
			tbReqCache.set(uname, 0);
			const deltaGb = cachedBytes / (1024 * 1024 * 1024);
			try {
				await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ? WHERE username = ?").bind(deltaGb, deltaGb, cachedReqs, uname).run();
			} catch (e) {
				console.error(e.message);
			} finally {
				tbWriteLock.delete(uname);
				if (activeCount <= 0) {
					tbLastActive.delete(uname);
					tbLastActive.delete(uname + "_hb");
				}
			}
		}
	}
}
function getSelectedUserProxy(userSocks5, request) {
	if (!userSocks5) return "";
	let proxyList = [];
	try {
		if (userSocks5.trim().startsWith("[")) {
			proxyList = JSON.parse(userSocks5);
		} else {
			proxyList = [userSocks5];
		}
	} catch (e) {
		proxyList = [userSocks5];
	}
	if (!Array.isArray(proxyList) || proxyList.length === 0) return "";
	let idx = 0;
	let locSpecified = false;
	if (request) {
		try {
			const url = new URL(request.url);
			const pathMatch = url.pathname.match(/\/loc-(\d+)/);
			if (pathMatch) {
				idx = parseInt(pathMatch[1], 10);
				locSpecified = true;
			} else {
				const locParam = url.searchParams.get("loc");
				if (locParam !== null && !isNaN(Number(locParam))) {
					idx = parseInt(locParam, 10);
					locSpecified = true;
				}
			}
		} catch (e) {}
	}
	if (locSpecified && idx >= proxyList.length) return "";
	if (idx < 0 || idx >= proxyList.length) idx = 0;
	const selected = proxyList[idx];
	if (selected === null || selected === undefined || selected === "") return "";
	if (typeof selected === "object" && selected !== null) {
		return String(selected.proxy || selected.url || "").trim();
	}
	return String(selected).trim();
}

const PROXIFLY_ALL_URL = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.json";
const PROXIFLY_ALL_URL_GH = "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.json";
const EXIT_PROXY_SOURCES = [
	{ name: "ProxyScrape", key: "proxyscrape", url: "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text&timeout=1000", type: "text" },
	{ name: "HProxy", key: "hproxy", url: "https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/all.json", type: "json" },
	{ name: "Databay", key: "databay", url: "https://databay.com/api/v1/proxy-list", type: "json" },
];
const EXIT_PING_CACHE_MS = 8 * 60 * 1000;
let _exitPingCache = {}; // { [cc]: { at, proxies } }
const EXIT_COUNTRY_NAMES = {
	DE: "Germany", US: "United States", NL: "Netherlands", GB: "United Kingdom", FR: "France",
	TR: "Turkey", CA: "Canada", SE: "Sweden", FI: "Finland", PL: "Poland", IT: "Italy",
	ES: "Spain", JP: "Japan", SG: "Singapore", KR: "South Korea", IN: "India",
	AU: "Australia", AT: "Austria", BE: "Belgium", BR: "Brazil", CH: "Switzerland",
	CZ: "Czechia", DK: "Denmark", IE: "Ireland", IL: "Israel", MX: "Mexico",
	NO: "Norway", PT: "Portugal", RO: "Romania", RU: "Russia", UA: "Ukraine",
	HK: "Hong Kong", TW: "Taiwan", TH: "Thailand", VN: "Vietnam", ID: "Indonesia",
	MY: "Malaysia", PH: "Philippines", AE: "United Arab Emirates", ZA: "South Africa",
};
let _proxiflyCache = { at: 0, list: null };
let _exitUniverseCache = { at: 0, list: null };
const PROXIFLY_TTL_MS = 8 * 60 * 1000;
const EXIT_UNIVERSE_TTL_MS = 10 * 60 * 1000;
async function fetchProxiflyList() {
	const now = Date.now();
	if (_proxiflyCache.list && now - _proxiflyCache.at < PROXIFLY_TTL_MS) return _proxiflyCache.list;
	const urls = [PROXIFLY_ALL_URL + "?t=" + now, PROXIFLY_ALL_URL_GH + "?t=" + now];
	for (const u of urls) {
		try {
			const res = await fetch(u, {
				headers: { Accept: "application/json", "User-Agent": "Mozilla/5.0" },
			});
			if (!res.ok) continue;
			const data = await res.json();
			const list = Array.isArray(data) ? data : [];
			if (list.length) {
				_proxiflyCache = { at: now, list };
				return list;
			}
		} catch (e) {}
	}
	return _proxiflyCache.list || [];
}
function parseExitTextLine(line, source) {
	let s = String(line || "").trim();
	if (!s || s[0] === "#" || s.startsWith("//")) return null;
	const m = s.match(/^(?:(socks5|socks4|socks|http|https):\/\/)?(?:([^@/\s]+)@)?\[?([a-zA-Z0-9._-]+)\]?:(\d{1,5})\s*$/i);
	if (!m) return null;
	let protocol = (m[1] || "unknown").toLowerCase();
	if (protocol === "socks") protocol = "socks5";
	const host = m[3];
	const port = parseInt(m[4], 10);
	if (!host || !port || host.includes(":")) return null;
	return {
		key: host + ":" + port,
		host,
		port,
		protocol,
		country: "",
		source,
		proxy: (protocol !== "unknown" ? protocol + "://" : "socks5://") + host + ":" + port,
	};
}
function parseExitProxiflyItem(item) {
	if (!item) return null;
	let country = "";
	if (item.geolocation && item.geolocation.country) {
		const c = item.geolocation.country;
		country = String(typeof c === "object" ? (c.iso_code || c) : c).toUpperCase();
	}
	if (item.proxy) {
		const p = parseExitTextLine(item.proxy, "proxifly");
		if (p) {
			p.country = country;
			if (item.protocol) p.protocol = String(item.protocol).toLowerCase();
			return p;
		}
	}
	const host = String(item.ip || item.host || "").trim();
	const port = parseInt(item.port, 10);
	if (!host || !port || host.includes(":")) return null;
	const protocol = String(item.protocol || "socks5").toLowerCase();
	return {
		key: host + ":" + port,
		host,
		port,
		protocol,
		country,
		source: "proxifly",
		proxy: protocol + "://" + host + ":" + port,
	};
}
function parseExitPrettyItem(item) {
	if (!item) return null;
	const host = String(item.host || item.ip || "").trim();
	const port = parseInt(item.port, 10);
	if (!host || !port || host.includes(":")) return null;
	let protocol = String(item.protocol || "socks5").toLowerCase();
	if (protocol === "socks") protocol = "socks5";
	let country = "";
	let countryName = "";
	try {
		const g = item.geolocation && item.geolocation.country;
		if (g) {
			country = String(g.iso_code || "").toUpperCase();
			if (g.names && g.names.en) countryName = String(g.names.en);
		}
	} catch (e) {}
	return {
		key: host + ":" + port,
		host,
		port,
		protocol,
		country,
		countryName,
		source: "monosans",
		timeout: typeof item.timeout === "number" ? item.timeout : null,
		proxy: protocol + "://" + host + ":" + port,
	};
}
async function lookupExitCountry(ip) {
	try {
		if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return "";
		const res = await fetch("http://ip-api.com/json/" + ip + "?fields=status,countryCode", { headers: { Accept: "application/json" } });
		if (!res.ok) return "";
		const data = await res.json();
		if (data && data.status === "success" && data.countryCode) return String(data.countryCode).toUpperCase();
	} catch (e) {}
	return "";
}
function parseExitProxyscrapeItem(item) {
	try {
		if (!item) return null;
		if (typeof item === "string") {
			const s = item.trim();
			if (!s) return null;
			let protocol = "http";
			let rest = s;
			const m = s.match(/^(socks5|socks4|socks|http|https):\/\/(.+)$/i);
			if (m) {
				protocol = m[1].toLowerCase();
				rest = m[2];
			}
			let host = rest;
			let port = "";
			if (rest.startsWith("[")) {
				const end = rest.indexOf("]");
				host = rest.slice(1, end);
				port = rest.slice(end + 1).replace(/^:/, "");
			} else {
				const idx = rest.lastIndexOf(":");
				if (idx > 0) {
					host = rest.slice(0, idx);
					port = rest.slice(idx + 1);
				}
			}
			if (!host || !port) return null;
			const proxy = protocol + "://" + host + ":" + port;
			return { proxy: proxy, protocol: protocol, ip: host, port: String(port), country: "", key: proxy };
		}
		if (typeof item === "object") {
			let protocol = String(item.protocol || item.type || "http").toLowerCase();
			if (protocol === "https") protocol = "http";
			const host = item.ip || item.host || item.proxy_address || item.address || "";
			const port = item.port || item.proxy_port || "";
			const country = String(item.country || item.countryCode || item.country_code || "").toUpperCase();
			if (!host || !port) {
				if (item.proxy && typeof item.proxy === "string") return parseExitProxyscrapeItem(item.proxy);
				return null;
			}
			const proxy = protocol + "://" + host + ":" + port;
			return { proxy: proxy, protocol: protocol, ip: String(host), port: String(port), country: country, key: proxy };
		}
	} catch (e) {}
	return null;
}
async function fetchExitProxyUniverse(geoBudget = 35) {
	const now = Date.now();
	if (_exitUniverseCache.list && now - _exitUniverseCache.at < EXIT_UNIVERSE_TTL_MS) return _exitUniverseCache.list;
	const out = [];
	const seen = new Set();
	await Promise.all(
		EXIT_PROXY_SOURCES.map(async (src) => {
			try {
				const res = await fetch(src.url + (src.url.includes("?") ? "&" : "?") + "t=" + now, {
					headers: { "User-Agent": "TrexBridge/1.0", Accept: "application/json,*/*" },
				});
				if (!res.ok) return;
				if (src.type === "proxyscrape") {
					const data = await res.json();
					let arr = [];
					if (Array.isArray(data)) arr = data;
					else if (data && Array.isArray(data.proxies)) arr = data.proxies;
					else if (data && typeof data === "object") {
						for (const v of Object.values(data)) {
							if (Array.isArray(v)) arr = arr.concat(v);
						}
					}
					for (const item of arr) {
						const p = parseExitProxyscrapeItem(item);
						if (p && !seen.has(p.key)) {
							seen.add(p.key);
							out.push(p);
						}
					}
				} else if (src.type === "pretty" || src.type === "json") {
					const data = await res.json();
					const arr = Array.isArray(data) ? data : [];
					for (const item of arr) {
						const p = src.type === "pretty" ? parseExitPrettyItem(item) : parseExitProxiflyItem(item);
						if (p && !seen.has(p.key)) {
							seen.add(p.key);
							out.push(p);
						}
					}
				} else {
					const textBody = await res.text();
					for (const line of textBody.split(/\r?\n/)) {
						const p = parseExitTextLine(line, src.name);
						if (p && !seen.has(p.key)) {
							seen.add(p.key);
							out.push(p);
						}
					}
				}
			} catch (e) {}
		}),
	);
	// Geo-detect only items still missing country (mostly rare gaps)
	const needGeo = out.filter((p) => !p.country && /^\d+\.\d+\.\d+\.\d+$/.test(p.host));
	for (let i = needGeo.length - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1));
		const t = needGeo[i];
		needGeo[i] = needGeo[j];
		needGeo[j] = t;
	}
	const sample = needGeo.slice(0, geoBudget);
	await Promise.all(
		sample.map(async (p) => {
			const cc = await lookupExitCountry(p.host);
			if (cc) p.country = cc;
		}),
	);
	_exitUniverseCache = { at: now, list: out };
	return out;
}
async function buildExitCountries() {
	const list = await fetchExitProxyUniverse(20);
	const map = {};
	for (const p of list) {
		const cc = (p.country || "").toUpperCase();
		if (!cc || cc.length !== 2) continue;
		if (!map[cc]) {
			map[cc] = {
				code: cc,
				name: cc, // abbreviation only (US, DE, …)
				count: 0,
				socks: 0,
			};
		}
		map[cc].count++;
		const pr = String(p.protocol || "").toLowerCase();
		if (pr.includes("socks")) map[cc].socks++;
	}
	return Object.values(map).sort((a, b) => a.code.localeCompare(b.code));
}
async function tcpPingExit(host, port, timeoutMs = 1100) {
	const start = Date.now();
	let sock = null;
	try {
		sock = connect({ hostname: host, port: Number(port) });
		const timer = new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), timeoutMs));
		await Promise.race([sock.opened, timer]);
		const ms = Date.now() - start;
		try { sock.close(); } catch (e) {}
		return ms;
	} catch (e) {
		try { sock && sock.close(); } catch (err) {}
		return null;
	}
}
function exitProtoRank(proto) {
	const p = String(proto || "").toLowerCase();
	if (p.includes("socks5")) return 0;
	if (p.includes("socks4")) return 1;
	if (p === "socks") return 1;
	if (p.includes("https")) return 3;
	if (p.includes("http")) return 4;
	return 2;
}
function isExitSocks(proto) {
	const p = String(proto || "").toLowerCase();
	return p.includes("socks");
}
async function buildExitProxiesForCountry(cc, maxTest = 40, topN = 12, force = false) {
	cc = String(cc || "").toUpperCase();
	if (!cc) return [];
	const cached = _exitPingCache[cc];
	if (!force && cached && cached.proxies && cached.proxies.length && Date.now() - cached.at < EXIT_PING_CACHE_MS) {
		return cached.proxies.slice(0, topN);
	}
	let list = await fetchExitProxyUniverse(30);
	let matched = list.filter((p) => (p.country || "").toUpperCase() === cc);
	if (matched.length < 6) {
		const unknown = list.filter((p) => !p.country && /^\d+\.\d+\.\d+\.\d+$/.test(String(p.host || "")));
		for (let i = unknown.length - 1; i > 0; i--) {
			const j = Math.floor(Math.random() * (i + 1));
			const t = unknown[i];
			unknown[i] = unknown[j];
			unknown[j] = t;
		}
		await Promise.all(
			unknown.slice(0, 16).map(async (p) => {
				try {
					const g = await lookupExitCountry(p.host);
					if (g) p.country = g;
				} catch (e) {}
			}),
		);
		matched = list.filter((p) => (p.country || "").toUpperCase() === cc);
	}
	// Sample: mix SOCKS + HTTP, shuffle for variety
	const socks = matched.filter((p) => isExitSocks(p.protocol));
	const httpOnly = matched.filter((p) => !isExitSocks(p.protocol));
	function shuffle(arr) {
		for (let i = arr.length - 1; i > 0; i--) {
			const j = Math.floor(Math.random() * (i + 1));
			const t = arr[i];
			arr[i] = arr[j];
			arr[j] = t;
		}
		return arr;
	}
	shuffle(socks);
	shuffle(httpOnly);
	const sample = [];
	// Prefer more SOCKS in sample but keep some HTTP
	for (const p of socks) {
		if (sample.length >= Math.min(maxTest, 32)) break;
		sample.push(p);
	}
	for (const p of httpOnly) {
		if (sample.length >= maxTest) break;
		sample.push(p);
	}
	// Phase 1: fast TCP open ping (parallel)
	const tcpHits = [];
	const concurrency = 18;
	let idx = 0;
	async function tcpWorker() {
		while (idx < sample.length) {
			const i = idx++;
			const item = sample[i];
			if (!item || !item.host || !item.port) continue;
			const ping = await tcpPingExit(item.host, item.port, 1100);
			if (ping == null) continue;
			const proxy = item.proxy || normalizeProxyUrl(item.host + ":" + item.port, item.protocol);
			if (!proxy) continue;
			tcpHits.push({
				proxy,
				host: item.host,
				port: item.port,
				protocol: item.protocol,
				country: cc,
				countryName: cc,
				source: item.source,
				ping,
				verified: false,
			});
		}
	}
	await Promise.all(Array.from({ length: Math.min(concurrency, Math.max(sample.length, 1)) }, () => tcpWorker()));
	// Lowest ping first (what user cares about)
	tcpHits.sort((a, b) => a.ping - b.ping);
	// Phase 2: verify CONNECT through proxy on the fastest candidates
	const verifyN = Math.min(tcpHits.length, Math.max(topN * 2, 16));
	const toVerify = tcpHits.slice(0, verifyN);
	const verified = [];
	let vIdx = 0;
	async function verifyWorker() {
		while (vIdx < toVerify.length) {
			const i = vIdx++;
			const item = toVerify[i];
			const ok = await testProxyAlive(item.proxy, 800);
			if (!ok) continue;
			item.verified = true;
			verified.push(item);
		}
	}
	await Promise.all(Array.from({ length: Math.min(10, toVerify.length || 1) }, () => verifyWorker()));
	verified.sort((a, b) => a.ping - b.ping);
	// Prefer verified; if none, fall back to TCP-only lowest ping (still usable sometimes)
	let top = verified.length ? verified.slice(0, topN) : tcpHits.slice(0, topN);
	// Soft prefer SOCKS among same ping band: stable secondary key
	top.sort((a, b) => {
		if (a.ping !== b.ping) return a.ping - b.ping;
		return exitProtoRank(a.protocol) - exitProtoRank(b.protocol);
	});
	_exitPingCache[cc] = { at: Date.now(), proxies: top };
	return top;
}
async function testProxyTcpOpen(host, port, timeoutMs = 2000) {
	if (!host || !port) return false;
	let sock = null;
	try {
		sock = connect({ hostname: String(host), port: Number(port) });
		const timer = new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), timeoutMs));
		await Promise.race([sock.opened, timer]);
		try { sock.close(); } catch (e) {}
		return true;
	} catch (e) {
		try { sock && sock.close(); } catch (err) {}
		return false;
	}
}
async function pickRandomExitProxy(maxTry = 24) {
	const list = await fetchExitProxyUniverse(25);
	if (!list.length) return null;
	const socks5 = list.filter((p) => String(p.protocol || "").toLowerCase().includes("socks5"));
	const socks4 = list.filter((p) => {
		const pr = String(p.protocol || "").toLowerCase();
		return pr.includes("socks4") || pr === "socks";
	});
	const http = list.filter((p) => !isExitSocks(p.protocol));
	const ordered = socks5.concat(socks4, http);
	for (let i = ordered.length - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1));
		const tmp = ordered[i];
		ordered[i] = ordered[j];
		ordered[j] = tmp;
	}
	ordered.sort((a, b) => exitProtoRank(a.protocol) - exitProtoRank(b.protocol));
	const tryN = Math.min(maxTry, ordered.length);
	let fallback = null;
	for (let i = 0; i < tryN; i++) {
		const item = ordered[i];
		const proxy = item.proxy || normalizeProxyUrl(item.host + ":" + item.port, item.protocol);
		if (!proxy) continue;
		if (!fallback) {
			fallback = item;
			fallback._proxy = proxy;
		}
		const start = Date.now();
		let ok = false;
		try {
			ok = await testProxyAlive(proxy, 800);
		} catch (e) {
			ok = false;
		}
		if (!ok) {
			try {
				ok = await testProxyTcpOpen(item.host, item.port, 1800);
			} catch (e) {
				ok = false;
			}
		}
		if (!ok) continue;
		const ping = Date.now() - start;
		let country = (item.country || "").toUpperCase();
		if (!country) {
			try { country = await lookupExitCountry(item.host); } catch (e) { country = ""; }
		}
		return {
			proxy,
			host: item.host,
			port: item.port,
			protocol: item.protocol,
			country: country || "",
			countryName: country || "",
			source: item.source || "proxifly",
			ping,
		};
	}
	if (fallback) {
		let country = (fallback.country || "").toUpperCase();
		if (!country) {
			try { country = await lookupExitCountry(fallback.host); } catch (e) { country = ""; }
		}
		return {
			proxy: fallback._proxy,
			host: fallback.host,
			port: fallback.port,
			protocol: fallback.protocol,
			country: country || "",
			countryName: country || "",
			source: fallback.source || "proxifly",
			ping: 0,
			untested: true,
		};
	}
	return null;
}
function normalizeProxyUrl(proxy, protocolHint) {
	let p = String(proxy || "").trim();
	if (!p) return "";
	if (/^(socks4|socks5|socks|http|https):\/\//i.test(p)) return p;
	const proto = String(protocolHint || "socks5").toLowerCase();
	if (proto.includes("http")) return "http://" + p;
	if (proto.includes("socks4")) return "socks4://" + p;
	return "socks5://" + p;
}
async function testProxyAlive(proxyUrl, timeoutMs = 900) {
	if (!proxyUrl) return false;
	let sock = null;
	const timeoutId = setTimeout(() => {
		try { sock && sock.close(); } catch (e) {}
	}, timeoutMs);
	try {
		const payload = TEXT_ENCODER.encode("GET /cdn-cgi/trace HTTP/1.1\r\nHost: cloudflare.com\r\nConnection: close\r\n\r\n");
		sock = await connectProxy(proxyUrl, "cloudflare.com", 80, payload);
		const reader = sock.readable.getReader();
		let buf = new Uint8Array(0);
		const deadline = Date.now() + timeoutMs;
		while (Date.now() < deadline) {
			const remaining = Math.max(50, deadline - Date.now());
			const res = await Promise.race([
				reader.read(),
				new Promise(function (resolve) {
					setTimeout(function () { resolve({ done: true, value: null, timeout: true }); }, remaining);
				}),
			]);
			if (!res || res.timeout) break;
			if (res.done) break;
			if (res.value && res.value.byteLength) {
				const merged = new Uint8Array(buf.length + res.value.byteLength);
				merged.set(buf, 0);
				merged.set(res.value, buf.length);
				buf = merged;
				if (buf.length >= 12) break;
			}
		}
		clearTimeout(timeoutId);
		try { reader.releaseLock(); } catch (eR) {}
		try { sock.close(); } catch (e) {}
		if (!buf.length) return false;
		const text = TEXT_DECODER.decode(buf.slice(0, Math.min(buf.length, 220)));
		if (/HTTP\/\d/i.test(text) || /fl=|ip=|colo=/i.test(text) || buf.length >= 16) return true;
		return false;
	} catch (e) {
		clearTimeout(timeoutId);
		try { sock && sock.close(); } catch (err) {}
		return false;
	}
}
async function pickProxiflyProxy(countryCode, maxTest = 8) {
	const cc = String(countryCode || "").trim().toUpperCase();
	if (!cc || cc === "OFF" || cc === "NONE" || cc === "CF" || cc === "AUTO") return "";
	// Lowest-ping verified proxies for this country
	try {
		const ranked = await buildExitProxiesForCountry(cc, Math.max(maxTest * 3, 24), maxTest, false);
		if (ranked.length) return ranked[0].proxy;
	} catch (e) {}
	const list = await fetchProxiflyList();
	if (!list.length) return "";
	let matched = list.filter((item) => {
		const c = item && item.geolocation && item.geolocation.country ? String(item.geolocation.country).toUpperCase() : "";
		return c === cc && (item.proxy || (item.ip && item.port));
	});
	if (!matched.length) return "";
	const rank = (item) => {
		const p = String(item.protocol || item.proxy || "").toLowerCase();
		if (p.includes("socks5")) return 0;
		if (p.includes("socks4") || p.includes("socks")) return 1;
		if (p.includes("https")) return 2;
		if (p.includes("http")) return 3;
		return 4;
	};
	matched.sort((a, b) => rank(a) - rank(b));
	for (let i = matched.length - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1));
		const t = matched[i];
		matched[i] = matched[j];
		matched[j] = t;
	}
	const tryCount = Math.min(maxTest, matched.length);
	for (let i = 0; i < tryCount; i++) {
		const item = matched[i];
		let proxy = item.proxy || (item.ip + ":" + item.port);
		proxy = normalizeProxyUrl(proxy, item.protocol);
		if (!proxy) continue;
		const ok = await testProxyAlive(proxy, 900);
		if (ok) return proxy;
	}
	return "";
}
async function resolveUserProxy(user, request) {
	// Locked manual proxy stays until dead (caller rotates via replaceBrokenProxy / retry)
	const manual = getSelectedUserProxy(user?.user_socks5, request);
	if (manual) return manual;
	const cc = (user?.user_proxy_iata || "").trim();
	if (cc) return await pickProxiflyProxy(cc, 8);
	return "";
}
function userHasExitLock(user) {
	// Hard lock only for country-IATA mode WITHOUT a fixed socks URL.
	// Random free proxies are stored in user_socks5 and must soft-fallback when dead.
	const socks = (user && user.user_socks5) ? String(user.user_socks5).trim() : "";
	if (socks) return false;
	const cc = (user?.user_proxy_iata || "").trim().toUpperCase();
	return !!(cc && cc !== "OFF" && cc !== "NONE" && cc !== "CF" && cc !== "AUTO");
}
function tbBase64UrlToBytes(b64url) {
	try {
		let s = String(b64url || "").replace(/-/g, "+").replace(/_/g, "/");
		while (s.length % 4) s += "=";
		const bin = atob(s);
		const out = new Uint8Array(bin.length);
		for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
		return out;
	} catch (e) {
		return null;
	}
}
async function handlevIees(env, _unused = null, ctx = null, request = null) {
	try {
	// soft concurrent limit per isolate — drop quietly instead of crashing (avoids 1101)
	try {
		let live = 0;
		for (const n of tbConnCount.values()) live += n || 0;
		if (live > 180) {
			return new Response(null, { status: 503, headers: { "Retry-After": "3" } });
		}
	} catch (_) {}
	let rawClientIP = request ? request.headers.get("CF-Connecting-IP") || "unknown" : "unknown";
	let clientIP = rawClientIP;
	if (rawClientIP !== "unknown") {
		if (rawClientIP.includes(":")) {
			const parts = rawClientIP.split(":");
			if (parts.length >= 4) {
				clientIP = parts.slice(0, 4).join(":") + "::/64";
			}
		} else if (rawClientIP.includes(".")) {
			const parts = rawClientIP.split(".");
			if (parts.length === 4) {
				clientIP = parts.slice(0, 3).join(".") + ".0/24";
			}
		}
	}
	const socketPair = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(socketPair);
	serverSock.accept();
	serverSock.binaryType = "arraybuffer";

	let username = null;
	let validUUID = null;
	let targetDns = "8.8.4.4";
	let targetDoh = "https://cloudflare-dns.com/dns-query";
	function addBytes(bytes) {
		if (bytes <= 0) return;
		if (!username) {
			uncountedBytes += bytes;
			return;
		}
		if (uncountedBytes > 0) {
			bytes += uncountedBytes;
			uncountedBytes = 0;
		}
		let current = tbTrafficMap.get(username) || 0;
		tbTrafficMap.set(username, current + bytes);
		tbLastActive.set(username, Date.now());
		// prevent unbounded Map growth under high churn
		if (tbTrafficMap.size > 4000) {
			try {
				const nowP = Date.now();
				for (const [k, ts] of tbLastActive) {
					if (nowP - (ts || 0) > 120000) {
						tbTrafficMap.delete(k);
						tbLastActive.delete(k);
						tbReqCache.delete(k);
						tbWriteLock.delete(k);
						tbLastWrite.delete(k);
						tbConnCount.delete(k);
					}
				}
			} catch (_) {}
		}
		if (tbWriteLock.get(username)) return;
		let lastDbWrite = tbLastWrite.get(username) || 0;
		let now = Date.now();
		let thresholdBytes = 100 * 1024 * 1024;
		if ((current >= thresholdBytes && now - lastDbWrite > 20000) || (current > 0 && now - lastDbWrite > 120000)) {
			tbWriteLock.set(username, true);
			let toCommit = tbTrafficMap.get(username) || 0;
			let toCommitReq = tbReqCache.get(username) || 0;
			if (toCommit <= 0 && toCommitReq <= 0) {
				tbWriteLock.set(username, false);
				return;
			}
			tbTrafficMap.set(username, (tbTrafficMap.get(username) || 0) - toCommit);
			tbReqCache.set(username, (tbReqCache.get(username) || 0) - toCommitReq);
			tbLastWrite.set(username, now);
			let deltaGb = toCommit / (1024 * 1024 * 1024);
			let writeTask = async () => {
				try {
					await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ? WHERE username = ?").bind(deltaGb, deltaGb, toCommitReq, username).run();
				} catch (e) {
					console.error(e.message);
					tbTrafficMap.set(username, (tbTrafficMap.get(username) || 0) + toCommit);
					tbReqCache.set(username, (tbReqCache.get(username) || 0) + toCommitReq);
				} finally {
					tbWriteLock.set(username, false);
				}
			};
			if (ctx) ctx.waitUntil(writeTask());
			else writeTask();
		}
	}
	let isOfflineSet = false;
	let hasCountedAsActive = false;
	const setOffline = () => {
		if (isOfflineSet) return;
		isOfflineSet = true;
		const uname = username;
		if (!uname) return;
		if (clientIP && clientIP !== "unknown" && validUUID) {
			const removeIpTask = async () => {
				try {
					const user = await env.DB.prepare("SELECT active_ips FROM users WHERE uuid = ?").bind(validUUID).first();
					if (user) {
						let activeIps = JSON.parse(user.active_ips || "{}");
						if (activeIps[clientIP]) {
							if (typeof activeIps[clientIP] === "object") {
								activeIps[clientIP].count = (activeIps[clientIP].count || 1) - 1;
								if (activeIps[clientIP].count <= 0) {
									delete activeIps[clientIP];
								}
							} else {
								delete activeIps[clientIP];
							}
							await env.DB.prepare("UPDATE users SET active_ips = ? WHERE uuid = ?").bind(JSON.stringify(activeIps), validUUID).run();
						}
					}
				} catch (e) {
					console.error(`[setOffline Task] Error: ${e.message}`);
				}
			};
			if (ctx) ctx.waitUntil(removeIpTask());
			else removeIpTask();
		}
		let activeCount = tbConnCount.get(uname) || 0;
		if (hasCountedAsActive) {
			activeCount = Math.max(0, activeCount - 1);
		}
		if (activeCount <= 0) {
			tbConnCount.delete(uname);
			let cachedBytes = tbTrafficMap.get(uname) || 0;
			let cachedReqs = tbReqCache.get(uname) || 0;
			if ((cachedBytes > 0 || cachedReqs > 0) && !tbWriteLock.get(uname)) {
				tbWriteLock.set(uname, true);
				tbTrafficMap.set(uname, (tbTrafficMap.get(uname) || 0) - cachedBytes);
				tbReqCache.set(uname, (tbReqCache.get(uname) || 0) - cachedReqs);
				const deltaGb = cachedBytes / (1024 * 1024 * 1024);
				const writeTask = async () => {
					try {
						await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ? WHERE username = ?").bind(deltaGb, deltaGb, cachedReqs, uname).run();
					} catch (e) {
						console.error(e.message);
						tbTrafficMap.set(uname, (tbTrafficMap.get(uname) || 0) + cachedBytes);
						tbReqCache.set(uname, (tbReqCache.get(uname) || 0) + cachedReqs);
					} finally {
						tbWriteLock.delete(uname);
						tbLastActive.delete(uname);
					}
				};
				if (ctx) {
					ctx.waitUntil(writeTask());
				} else {
					writeTask();
				}
			} else {
				tbLastActive.delete(uname);
			}
		} else {
			tbConnCount.set(uname, activeCount);
		}
	};
	let heartbeat;
	const runHeartbeat = async () => {
		if (serverSock.readyState === WebSocket.OPEN) {
			try {
				serverSock.send(new Uint8Array(0));
				if (!validUUID || !username) {
					heartbeat = setTimeout(runHeartbeat, Math.floor(Math.random() * 5000) + 20000);
					return;
				}
				const nowTime = Date.now();
				const lastCheck = tbLastActive.get(username + "_hb") || 0;
				if (nowTime - lastCheck >= 20000) {
					tbLastActive.set(username + "_hb", nowTime);
					const user = await env.DB.prepare("SELECT is_active, limit_gb, used_gb, limit_req, used_req, expiry_days, created_at, ip_limit, active_ips FROM users WHERE uuid = ?").bind(validUUID).first();
					let isExpired = false;
					let isIpLimitExpired = false;
					let updatedActiveIps = null;
					if (!user || user.is_active === 0) {
						isExpired = true;
					} else {
						if (user.limit_gb && user.used_gb >= user.limit_gb) isExpired = true;
						if (user.limit_req && user.used_req + (tbReqCache.get(username) || 0) >= user.limit_req) isExpired = true;
						if (user.expiry_days && user.created_at) {
							const expiryDate = new Date(new Date(user.created_at).getTime() + user.expiry_days * 86400000);
							if (nowTime > expiryDate.getTime()) isExpired = true;
						}
						if (!isExpired && clientIP && clientIP !== "unknown") {
							let activeIps = {};
							try {
								activeIps = JSON.parse(user.active_ips || "{}");
							} catch (e) {}
							let hasChanges = false;
							for (const [ip, data] of Object.entries(activeIps)) {
								const lastSeen = data && typeof data === "object" ? data.timestamp : data;
								if (nowTime - lastSeen > 20000) {
									delete activeIps[ip];
									hasChanges = true;
								}
							}
							if (!activeIps[clientIP]) {
								isIpLimitExpired = true;
							} else {
								const sortedIps = Object.keys(activeIps).sort((a, b) => {
									const tA = typeof activeIps[a] === "object" ? activeIps[a].timestamp : activeIps[a];
									const tB = typeof activeIps[b] === "object" ? activeIps[b].timestamp : activeIps[b];
									return tB - tA;
								});
								if (user.ip_limit && user.ip_limit > 0 && sortedIps.indexOf(clientIP) >= user.ip_limit) isIpLimitExpired = true;
							}
							if (hasChanges || isIpLimitExpired) updatedActiveIps = JSON.stringify(activeIps);
						}
					}
					if (isExpired) {
						await env.DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(validUUID).run();
						clearTimeout(heartbeat);
						closeSocketQuietly(serverSock);
						return;
					}
					if (isIpLimitExpired) {
						clearTimeout(heartbeat);
						closeSocketQuietly(serverSock);
						return;
					}
					if (updatedActiveIps !== null) {
						await env.DB.prepare("UPDATE users SET last_active = ?, active_ips = ? WHERE username = ?").bind(nowTime, updatedActiveIps, username).run();
					} else {
						await env.DB.prepare("UPDATE users SET last_active = ? WHERE username = ?").bind(nowTime, username).run();
					}
				}
			} catch (e) {}
			heartbeat = setTimeout(runHeartbeat, Math.floor(Math.random() * 5000) + 20000);
		} else {
			clearTimeout(heartbeat);
		}
	};
	heartbeat = setTimeout(runHeartbeat, Math.floor(Math.random() * 5000) + 20000);
	let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
	let reqUUID = null;
	let isHeaderParsed = false;
	let isHeaderParsing = false;
	let isDnsQuery = false;
	let chunkBuffer = new Uint8Array(0);
	let uncountedBytes = 0;
	let wsChain = Promise.resolve();
	let wsStopped = false,
		wsFailed = false,
		wsFinished = false;
	let wsQueueBytes = 0,
		wsQueueItems = 0;
	let currentSocketWriter = null,
		activeRemoteWriter = null;
	const releaseRemoteWriter = () => {
		if (activeRemoteWriter) {
			try {
				activeRemoteWriter.releaseLock();
			} catch (e) {}
			activeRemoteWriter = null;
		}
		currentSocketWriter = null;
	};
	const getRemoteWriter = () => {
		const s = remoteConnWrapper.socket;
		if (!s) return null;
		if (s !== currentSocketWriter) {
			releaseRemoteWriter();
			currentSocketWriter = s;
			activeRemoteWriter = s.writable.getWriter();
		}
		return activeRemoteWriter;
	};
	const upstreamQueue = createUpstreamQueue({
		getWriter: getRemoteWriter,
		releaseWriter: releaseRemoteWriter,
		retryConnect: async () => {
			if (typeof remoteConnWrapper.retryConnect === "function") {
				await remoteConnWrapper.retryConnect();
			}
		},
		closeConnection: () => {
			try {
				remoteConnWrapper.socket?.close();
			} catch (e) {}
			closeSocketQuietly(serverSock);
		},
		name: "vIeesWSQueue",
	});
	const writeToRemote = async (chunk, allowRetry = true) => {
		return upstreamQueue.writeAndAwait(chunk, allowRetry);
	};
	const processWsMessage = async (chunk) => {
		const bytes = chunk.byteLength || 0;
		if (isHeaderParsed) addBytes(bytes);
		if (isDnsQuery) {
			await forwardvIeesUDP(chunk, serverSock, null, null, targetDns);
			return;
		}
		if (isHeaderParsed) {
			if (remoteConnWrapper.connectingPromise) {
				await remoteConnWrapper.connectingPromise;
			}
			try { await writeToRemote(chunk); } catch (_) { try { closeSocketQuietly(serverSock); } catch(__){} return; }
			return;
		}
		if (!isHeaderParsed) {
			chunkBuffer = concatBytes(chunkBuffer, chunk);
			/* ---- alt auth ---- */
			// alt header path
			if (chunkBuffer.byteLength > 0) {
				const b0 = chunkBuffer[0];
				const hexStart = (b0 >= 48 && b0 <= 57) || (b0 >= 97 && b0 <= 102) || (b0 >= 65 && b0 <= 70);
				if (hexStart && chunkBuffer.byteLength < 58) return;
			}
			if (chunkBuffer.byteLength >= 58 && isLikelyAuthHeader(chunkBuffer)) {
				const trojan = parseAuthHeader(chunkBuffer);
				if (trojan && trojan.needMore) return;
				if (!trojan) {
					serverSock.close();
					return;
				}
				if (isHeaderParsing) return;
				isHeaderParsing = true;
				try {
					let user = null;
					let uuidTail = "";
					if (request) {
						try {
							const p = new URL(request.url).pathname || "";
							const m = p.match(/\/api\/ws(?:\/([A-Za-z0-9]+))?/i);
							if (m) uuidTail = m[1];
						} catch (e) {}
					}
					if (uuidTail) {
						user = await env.DB.prepare("SELECT * FROM users WHERE uuid LIKE ?").bind("%-" + uuidTail).first();
					}
					if (!user) {
						const { results: candidates } = await env.DB.prepare("SELECT * FROM users WHERE is_active = 1").all();
						for (const cand of candidates || []) {
							if (sha224Hex(cand.uuid || "") === trojan.hash || sha224Hex(String(cand.uuid || "").replace(/-/g, "")) === trojan.hash) {
								user = cand;
								break;
							}
						}
					}
					if (!user) {
						serverSock.close();
						return;
					}
					{
						const u = String(user.uuid || "");
						const okHash =
							sha224Hex(u) === trojan.hash ||
							sha224Hex(u.replace(/-/g, "")) === trojan.hash ||
							sha224Hex(u.toLowerCase()) === trojan.hash ||
							sha224Hex(u.replace(/-/g, "").toLowerCase()) === trojan.hash;
						if (!okHash) {
							serverSock.close();
							return;
						}
					}
					if (request) {
						const reqUrl = new URL(request.url);
						const p = reqUrl.pathname || "";
						const pathOk = !p || p === "/" || p.includes("/api/ws") || p.includes("ws") || p.includes("/api/");
						// allow path variants from different clients
					}
					username = user.username;
					validUUID = user.uuid;
					reqUUID = user.uuid;
					let currentReqs = tbReqCache.get(username) || 0;
					tbReqCache.set(username, currentReqs + 1);
					if (!tbTrafficMap.has(username)) tbTrafficMap.set(username, 0);
					if (isOfflineSet || serverSock.readyState !== WebSocket.OPEN) return;
					if (user.is_active === 0) { serverSock.close(); return; }
					if (user.limit_gb && user.used_gb >= user.limit_gb) { serverSock.close(); return; }
					if (user.limit_req && user.used_req + (tbReqCache.get(username) || 0) > user.limit_req) { serverSock.close(); return; }
					if (user.expiry_days && user.created_at) {
						const created = new Date(user.created_at);
						const expiryDate = new Date(created.getTime() + user.expiry_days * 24 * 60 * 60 * 1000);
						if (new Date() > expiryDate) {
							try { await env.DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(user.uuid).run(); } catch (e) {}
							serverSock.close();
							return;
						}
					}

					try {
						let _fx = null;
						try { if (user.frag_len && String(user.frag_len).trim().charAt(0) === "{") _fx = JSON.parse(String(user.frag_len)); } catch (e0) {}
						if (_fx && _fx.block_malware) {
							targetDns = "1.1.1.2";
							targetDoh = "https://security.cloudflare-dns.com/dns-query";
						}
						if (user.block_porn === 1 && user.block_ads === 1) {
							targetDns = "94.140.14.15";
							targetDoh = "https://family.adguard-dns.com/dns-query";
						} else if (user.block_porn === 1) {
							targetDns = "1.1.1.3";
							targetDoh = "https://family.cloudflare-dns.com/dns-query";
						} else if (user.block_ads === 1) {
							targetDns = "94.140.14.14";
							targetDoh = "https://dns.adguard-dns.com/dns-query";
						}
						const _blocked = [];
						if (_fx && Array.isArray(_fx.block_hosts)) _fx.block_hosts.forEach(function(d){ if (d) _blocked.push(String(d).toLowerCase()); });
						if (_fx && _fx.block_gambling) ["bet365.com","pokerstars.com","casino.com","gambling.com","stake.com","1xbet.com","betfair.com"].forEach(function(d){ _blocked.push(d); });
						if (_fx && _fx.block_social) ["instagram.com","tiktok.com","facebook.com","twitter.com","x.com","snapchat.com","reddit.com"].forEach(function(d){ _blocked.push(d); });
						// hostname checked later when addr known
						user.__tbBlockHosts = _blocked;
					} catch (eBlk) {}

					if (clientIP && clientIP !== "unknown") {
						let activeIps = {};
						try { activeIps = JSON.parse(user.active_ips || "{}"); } catch (e) {}
						const now = Date.now();
						for (const [ip, data] of Object.entries(activeIps)) {
							const lastSeen = data && typeof data === "object" ? data.timestamp : data;
							if (now - lastSeen > 20000) delete activeIps[ip];
						}
						let isNewIp = false;
						if (!activeIps[clientIP]) {
							const sortedIps = Object.keys(activeIps);
							if (user.ip_limit && user.ip_limit > 0 && sortedIps.length >= user.ip_limit) {
								serverSock.close();
								return;
							}
							activeIps[clientIP] = { timestamp: now, count: 1 };
							isNewIp = true;
						} else {
							if (typeof activeIps[clientIP] === "object") {
								activeIps[clientIP].timestamp = now;
								activeIps[clientIP].count = (activeIps[clientIP].count || 0) + 1;
							} else {
								activeIps[clientIP] = { timestamp: now, count: 1 };
							}
						}
						const lastWrite = tbLastActive.get(username) || 0;
						if (isNewIp || now - lastWrite > 30000) {
							tbLastActive.set(username, now);
							const updateTask = async () => {
								try {
									await env.DB.prepare("UPDATE users SET active_ips = ?, last_active = ? WHERE uuid = ?").bind(JSON.stringify(activeIps), now, user.uuid).run();
								} catch (e) {}
							};
							if (ctx) ctx.waitUntil(updateTask());
							else updateTask();
						}
					}
					isHeaderParsed = true;
					let activeCount = tbConnCount.get(username) || 0;
					tbConnCount.set(username, activeCount + 1);
					hasCountedAsActive = true;
					if (activeCount === 0) {
						const setOnlineTask = async () => {
							try {
								const now = Date.now();
								tbLastActive.set(username, now);
								await env.DB.prepare("UPDATE users SET last_active = ? WHERE username = ?").bind(now, username).run();
							} catch (e) {}
						};
						if (ctx) ctx.waitUntil(setOnlineTask());
						else setOnlineTask();
					}
					let addr = trojan.addr;
					const port = trojan.port;
					const cmd = trojan.cmd;
					const rawData = trojan.payload;
					const respHeader = null;
					if (cmd === 0x03) {
						if (port === 53) {
							isDnsQuery = true;
							await forwardvIeesUDP(rawData, serverSock, respHeader, addBytes, targetDns);
						} else {
							serverSock.close();
						}
						return;
					}
					if (port === 25 || port === 22 || /^(0\.|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|localhost$|::1|::ffff:|fd[0-9a-f]{2}:|fe80:)/i.test(addr)) {
						serverSock.close();
						return;
					}
										if (user.__tbBlockHosts && user.__tbBlockHosts.length && addr && !/^\d+\.\d+\.\d+\.\d+$/.test(addr)) {
						const hl = String(addr).toLowerCase();
						for (let bi = 0; bi < user.__tbBlockHosts.length; bi++) {
							const bd = user.__tbBlockHosts[bi];
							if (hl === bd || hl.endsWith("." + bd)) {
								try { serverSock.close(); } catch (eC) {}
								return;
							}
						}
					}
					if ((user.block_ads === 1 || user.block_porn === 1) && port !== 53 && addr && !/^\d+\.\d+\.\d+\.\d+$/.test(addr) && addr.indexOf(":") < 0) {
						try {
							const dnsCheck = await dohQuery(addr, "A", targetDoh);
							const isBlocked = dnsCheck.some((r) => r.data === "0.0.0.0" || r.data === "::" || r.data === "176.103.130.130");
							if (isBlocked) { serverSock.close(); return; }
							const resolvedRecord = dnsCheck.find((r) => r.type === 1 || r.type === 28);
							if (resolvedRecord && resolvedRecord.data) addr = resolvedRecord.data;
						} catch (e) {}
					}
					const connectTCP = async (dataPayload = null) => {
						if (remoteConnWrapper.connectingPromise) {
							await remoteConnWrapper.connectingPromise;
							return;
						}
						const task = (async () => {
							let s = null;
							const exitLocked = userHasExitLock(user);
							const socks5 = await resolveUserProxy(user, request);
							if (exitLocked) {
								// Location locked: try lowest-ping proxies for this country (never direct CF)
								const tried = new Set();
								let lastErr = null;
								const tryList = [];
								if (socks5) tryList.push(socks5);
								try {
									const ranked = await buildExitProxiesForCountry(String(user.user_proxy_iata || "").toUpperCase(), 24, 8, false);
									for (const r of ranked) {
										if (r && r.proxy) tryList.push(r.proxy);
									}
								} catch (e) {}
								try {
									const extra = await pickProxiflyProxy(user.user_proxy_iata, 6);
									if (extra) tryList.push(extra);
								} catch (e) {}
								for (const pxy of tryList) {
									if (!pxy || tried.has(pxy)) continue;
									tried.add(pxy);
									try {
										s = await connectProxy(pxy, addr, port, dataPayload);
										lastErr = null;
										break;
									} catch (e) {
										lastErr = e;
									}
								}
								if (!s) throw lastErr || new Error("exit_proxy_unavailable");
							} else if (socks5) {
								try {
									s = await connectProxy(socks5, addr, port, dataPayload);
								} catch (proxyErr) {
									if (user.auto_rotate_user_proxy === 1) {
										const replaceTask = replaceBrokenProxy(user.username, env, socks5);
										if (ctx) ctx.waitUntil(replaceTask);
										else replaceTask.catch(() => {});
									}
									// Fallback to direct so a dead manual proxy does not kill all pings
									s = await connectDirect(addr, port, dataPayload, targetDoh);
								}
							} else {
								s = await connectDirect(addr, port, dataPayload, targetDoh);
							}
							remoteConnWrapper.socket = s;
							s.closed.catch(() => {}).finally(() => closeSocketQuietly(serverSock));
							connectStreams(s, serverSock, (typeof respHeaderSent !== "undefined" && respHeaderSent) ? null : respHeader, null, addBytes);
						})();
						remoteConnWrapper.connectingPromise = task;
						try { await task; }
						finally {
							if (remoteConnWrapper.connectingPromise === task) remoteConnWrapper.connectingPromise = null;
						}
					};
					remoteConnWrapper.retryConnect = async () => connectTCP(null);
					await connectTCP(rawData);
				} catch (e) {
					serverSock.close();
				}
				return;
			}
			/* ---- primary ---- */
			if (chunkBuffer.byteLength < 24) return;
			let optLen = chunkBuffer[17];
			let requiredLen = 18 + optLen + 4;
			if (chunkBuffer.byteLength < requiredLen) return;
			let addrType = chunkBuffer[18 + optLen + 3];
			if (addrType === 1) {
				requiredLen += 4;
			} else if (addrType === 2) {
				requiredLen += 1;
				if (chunkBuffer.byteLength < requiredLen) return;
				requiredLen += chunkBuffer[18 + optLen + 4];
			} else if (addrType === 3) {
				requiredLen += 16;
			} else {
				serverSock.close();
				return;
			}
			if (chunkBuffer.byteLength < requiredLen) return;
			if (isHeaderParsing) return;
			isHeaderParsing = true;
			reqUUID = extractUUIDFromvIees(chunkBuffer);
			if (!reqUUID) {
				serverSock.close();
				return;
			}
			let user = null;
			try {
				user = await env.DB.prepare("SELECT * FROM users WHERE lower(uuid) = lower(?)").bind(reqUUID).first();
			} catch (e) {}
			if (!user) {
				serverSock.close();
				return;
			}
			if (request) {
				const reqUrl = new URL(request.url);
				const p = reqUrl.pathname || "";
				const pathOk = !p || p === "/" || p.includes("/api/ws") || p.includes("ws") || p.includes("/api/");
				// allow path variants from different clients
			}
			username = user.username;
			validUUID = reqUUID;
			let currentReqs = tbReqCache.get(username) || 0;
			tbReqCache.set(username, currentReqs + 1);
			if (!tbTrafficMap.has(username)) {
				tbTrafficMap.set(username, 0);
			}
			if (isOfflineSet || serverSock.readyState !== WebSocket.OPEN) {
				return;
			}
			if (user.is_active === 0) {
				serverSock.close();
				return;
			}
			if (user.limit_gb && user.used_gb >= user.limit_gb) {
				serverSock.close();
				return;
			}
			if (user.limit_req && user.used_req + (tbReqCache.get(username) || 0) > user.limit_req) {
				serverSock.close();
				return;
			}
			if (user.expiry_days && user.created_at) {
				const created = new Date(user.created_at);
				const expiryDate = new Date(created.getTime() + user.expiry_days * 24 * 60 * 60 * 1000);
				if (new Date() > expiryDate) {
					try {
						await env.DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(reqUUID).run();
					} catch (e) {}
					serverSock.close();
					return;
				}
			}
			try {
				let _fx2 = null;
				try { if (user.frag_len && String(user.frag_len).trim().charAt(0) === "{") _fx2 = JSON.parse(String(user.frag_len)); } catch (e0) {}
				if (_fx2 && _fx2.block_malware) {
					targetDns = "1.1.1.2";
					targetDoh = "https://security.cloudflare-dns.com/dns-query";
				}
				if (user.block_porn === 1 && user.block_ads === 1) {
					targetDns = "94.140.14.15";
					targetDoh = "https://family.adguard-dns.com/dns-query";
				} else if (user.block_porn === 1) {
					targetDns = "1.1.1.3";
					targetDoh = "https://family.cloudflare-dns.com/dns-query";
				} else if (user.block_ads === 1) {
					targetDns = "94.140.14.14";
					targetDoh = "https://dns.adguard-dns.com/dns-query";
				}
				const _blocked2 = [];
				if (_fx2 && Array.isArray(_fx2.block_hosts)) _fx2.block_hosts.forEach(function(d){ if (d) _blocked2.push(String(d).toLowerCase()); });
				if (_fx2 && _fx2.block_gambling) ["bet365.com","pokerstars.com","casino.com","gambling.com","stake.com","1xbet.com","betfair.com"].forEach(function(d){ _blocked2.push(d); });
				if (_fx2 && _fx2.block_social) ["instagram.com","tiktok.com","facebook.com","twitter.com","x.com","snapchat.com","reddit.com"].forEach(function(d){ _blocked2.push(d); });
				user.__tbBlockHosts = _blocked2;
			} catch (eBlk2) {}
			if (clientIP && clientIP !== "unknown") {
				let activeIps = {};
				try {
					activeIps = JSON.parse(user.active_ips || "{}");
				} catch (e) {}
				const now = Date.now();
				for (const [ip, data] of Object.entries(activeIps)) {
					const lastSeen = data && typeof data === "object" ? data.timestamp : data;
					if (now - lastSeen > 20000) delete activeIps[ip];
				}
				let isNewIp = false;
				if (!activeIps[clientIP]) {
					const sortedIps = Object.keys(activeIps);
					if (user.ip_limit && user.ip_limit > 0 && sortedIps.length >= user.ip_limit) {
						serverSock.close();
						return;
					}
					activeIps[clientIP] = { timestamp: now, count: 1 };
					isNewIp = true;
				} else {
					if (typeof activeIps[clientIP] === "object") {
						activeIps[clientIP].timestamp = now;
						activeIps[clientIP].count = (activeIps[clientIP].count || 0) + 1;
					} else {
						activeIps[clientIP] = { timestamp: now, count: 1 };
					}
				}
				const lastWrite = tbLastActive.get(username) || 0;
				if (isNewIp || now - lastWrite > 30000) {
					tbLastActive.set(username, now);
					const updateTask = async () => {
						try {
							await env.DB.prepare("UPDATE users SET active_ips = ?, last_active = ? WHERE uuid = ?").bind(JSON.stringify(activeIps), now, reqUUID).run();
						} catch (e) {}
					};
					if (ctx) ctx.waitUntil(updateTask());
					else updateTask();
				}
			}
			isHeaderParsed = true;
			let activeCount = tbConnCount.get(username) || 0;
			tbConnCount.set(username, activeCount + 1);
			hasCountedAsActive = true;
			if (activeCount === 0) {
				const setOnlineTask = async () => {
					try {
						const now = Date.now();
						tbLastActive.set(username, now);
						await env.DB.prepare("UPDATE users SET last_active = ? WHERE username = ?").bind(now, username).run();
					} catch (e) {}
				};
				if (ctx) ctx.waitUntil(setOnlineTask());
				else setOnlineTask();
			}
			try {
				let offset = 17;
				const optLen = chunkBuffer[offset++];
				offset += optLen;
				const cmd = chunkBuffer[offset++];
				const port = (chunkBuffer[offset++] << 8) | chunkBuffer[offset++];
				const addrType = chunkBuffer[offset++];
				let addr = "";
				if (addrType === 1) {
					addr = `${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}`;
				} else if (addrType === 2) {
					const domainLen = chunkBuffer[offset++];
					addr = TEXT_DECODER.decode(chunkBuffer.slice(offset, offset + domainLen));
					offset += domainLen;
				} else if (addrType === 3) {
					const v6 = [];
					for (let i = 0; i < 8; i++) {
						v6.push(((chunkBuffer[offset++] << 8) | chunkBuffer[offset++]).toString(16));
					}
					addr = v6.join(":");
				}
				const rawData = chunkBuffer.slice(offset);
				const respHeader = new Uint8Array([chunkBuffer[0], 0]);
				// CRITICAL: send VLESS response header immediately so client gets handshake (ping works even if remote is slow)
				try {
					if (serverSock.readyState === 1) serverSock.send(respHeader);
				} catch (eHdr) {}
				const respHeaderSent = true;
									if (user.__tbBlockHosts && user.__tbBlockHosts.length && addr && !/^\d+\.\d+\.\d+\.\d+$/.test(addr)) {
						const hl = String(addr).toLowerCase();
						for (let bi = 0; bi < user.__tbBlockHosts.length; bi++) {
							const bd = user.__tbBlockHosts[bi];
							if (hl === bd || hl.endsWith("." + bd)) {
								try { serverSock.close(); } catch (eC) {}
								return;
							}
						}
					}
					if ((user.block_ads === 1 || user.block_porn === 1) && addrType === 2 && port !== 53) {
					try {
						const dnsCheck = await dohQuery(addr, "A", targetDoh);
						const isBlocked = dnsCheck.some((r) => r.data === "0.0.0.0" || r.data === "::" || r.data === "176.103.130.130");
						if (isBlocked) {
							serverSock.close();
							return;
						}
						const resolvedRecord = dnsCheck.find((r) => r.type === 1 || r.type === 28);
						if (resolvedRecord && resolvedRecord.data) {
							addr = resolvedRecord.data;
						}
					} catch (e) {}
				}
				if (cmd === 2) {
					if (port === 53) {
						isDnsQuery = true;
						await forwardvIeesUDP(rawData, serverSock, respHeader, addBytes, targetDns);
					} else {
						serverSock.close();
					}
					return;
				}
				if (port === 25 || port === 22 || /^(0\.|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|localhost$|::1|::ffff:|fd[0-9a-f]{2}:|fe80:)/i.test(addr)) {
					serverSock.close();
					return;
				}
				const connectTCP = async (dataPayload = null, useFallback = true) => {
					if (remoteConnWrapper.connectingPromise) {
						await remoteConnWrapper.connectingPromise;
						return;
					}
					const task = (async () => {
						let s = null;
							const exitLocked = userHasExitLock(user);
							const socks5 = await resolveUserProxy(user, request);
							if (exitLocked) {
								// Location locked: try lowest-ping proxies for this country (never direct CF)
								const tried = new Set();
								let lastErr = null;
								const tryList = [];
								if (socks5) tryList.push(socks5);
								try {
									const ranked = await buildExitProxiesForCountry(String(user.user_proxy_iata || "").toUpperCase(), 24, 8, false);
									for (const r of ranked) {
										if (r && r.proxy) tryList.push(r.proxy);
									}
								} catch (e) {}
								try {
									const extra = await pickProxiflyProxy(user.user_proxy_iata, 6);
									if (extra) tryList.push(extra);
								} catch (e) {}
								for (const pxy of tryList) {
									if (!pxy || tried.has(pxy)) continue;
									tried.add(pxy);
									try {
										s = await connectProxy(pxy, addr, port, dataPayload);
										lastErr = null;
										break;
									} catch (e) {
										lastErr = e;
									}
								}
								if (!s) throw lastErr || new Error("exit_proxy_unavailable");
							} else if (socks5) {
								try {
									s = await connectProxy(socks5, addr, port, dataPayload);
								} catch (proxyErr) {
									if (user.auto_rotate_user_proxy === 1) {
										const replaceTask = replaceBrokenProxy(user.username, env, socks5);
										if (ctx) ctx.waitUntil(replaceTask);
										else replaceTask.catch(() => {});
									}
									// Fallback to direct so a dead manual proxy does not kill all pings
									s = await connectDirect(addr, port, dataPayload, targetDoh);
								}
							} else {
								s = await connectDirect(addr, port, dataPayload, targetDoh);
							}
						remoteConnWrapper.socket = s;
						s.closed.catch(() => {}).finally(() => closeSocketQuietly(serverSock));
						connectStreams(s, serverSock, (typeof respHeaderSent !== "undefined" && respHeaderSent) ? null : respHeader, null, addBytes);
					})();
					remoteConnWrapper.connectingPromise = task;
					try {
						await task;
					} finally {
						if (remoteConnWrapper.connectingPromise === task) {
							remoteConnWrapper.connectingPromise = null;
						}
					}
				};
				remoteConnWrapper.retryConnect = async () => connectTCP(null, false);
				await connectTCP(rawData, true);
			} catch (e) {
				serverSock.close();
			}
		}
	};
	const handleWsError = (err) => {
		if (wsFailed) return;
		wsFailed = true;
		wsStopped = true;
		clearTimeout(heartbeat);
		wsQueueBytes = 0;
		wsQueueItems = 0;
		upstreamQueue.clear();
		releaseRemoteWriter();
		closeSocketQuietly(serverSock);
		setOffline();
	};
	const pushToChain = (task) => {
		wsChain = wsChain.then(task).catch(handleWsError);
	};
	serverSock.addEventListener("message", (event) => {
		if (wsStopped || wsFailed) return;
		let data = event.data;
		if (typeof data === "string") {
			data = TEXT_ENCODER.encode(data);
		} else if (data instanceof ArrayBuffer) {
			data = new Uint8Array(data);
		} else if (ArrayBuffer.isView(data)) {
			data = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
		} else {
			return;
		}
		const size = data.byteLength || 0;
		if (!size) return;
		const nextBytes = wsQueueBytes + size;
		const nextItems = wsQueueItems + 1;
		if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
			handleWsError(new Error("ws queue overflow"));
			return;
		}
		wsQueueBytes = nextBytes;
		wsQueueItems = nextItems;
		pushToChain(async () => {
			wsQueueBytes = Math.max(0, wsQueueBytes - size);
			wsQueueItems = Math.max(0, wsQueueItems - 1);
			if (wsFailed) return;
			await processWsMessage(data);
		});
	});
	serverSock.addEventListener("close", () => {
		clearTimeout(heartbeat);
		closeSocketQuietly(serverSock);
		setOffline();
		if (wsFinished) return;
		wsFinished = true;
		wsStopped = true;
		pushToChain(async () => {
			if (wsFailed) return;
			await upstreamQueue.awaitEmpty();
			releaseRemoteWriter();
		});
	});
	serverSock.addEventListener("error", (err) => {
		handleWsError(err);
	});
	// 0-RTT / early data (sec-websocket-protocol)
	try {
		const edHeader = (request && request.headers.get("sec-websocket-protocol")) || "";
		if (edHeader) {
			const parts = edHeader.split(",").map(function (x) { return String(x || "").trim(); }).filter(Boolean);
			for (let ei = 0; ei < parts.length; ei++) {
				let token = parts[ei];
				if (/^0-/.test(token)) token = token.slice(2);
				const edBytes = tbBase64UrlToBytes(token);
				if (edBytes && edBytes.byteLength >= 18) {
					const size = edBytes.byteLength;
					const nextBytes = wsQueueBytes + size;
					const nextItems = wsQueueItems + 1;
					if (nextBytes <= UPSTREAM_QUEUE_MAX_BYTES && nextItems <= UPSTREAM_QUEUE_MAX_ITEMS) {
						wsQueueBytes = nextBytes;
						wsQueueItems = nextItems;
						pushToChain(async () => {
							wsQueueBytes = Math.max(0, wsQueueBytes - size);
							wsQueueItems = Math.max(0, wsQueueItems - 1);
							if (wsFailed) return;
							await processWsMessage(edBytes);
						});
					}
					break;
				}
			}
		}
	} catch (eEd) {}
	return new Response(null, { status: 101, webSocket: clientSock });
	} catch (outerErr) {
		try {
			return new Response("Internal Server Error", { status: 500 });
		} catch (_) {
			return new Response(null, { status: 500 });
		}
	}
}

function isIPv4(value) {
	const parts = String(value || "").split(".");
	return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}
function convertToUint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}
function concatBytes(...chunkList) {
	if (chunkList.length === 2) {
		const a = convertToUint8Array(chunkList[0]);
		const b = convertToUint8Array(chunkList[1]);
		if (!a.byteLength) return b;
		if (!b.byteLength) return a;
		const merged = new Uint8Array(a.byteLength + b.byteLength);
		merged.set(a, 0);
		merged.set(b, a.byteLength);
		return merged;
	}
	const chunks = chunkList.map(convertToUint8Array);
	let total = 0;
	for (const c of chunks) total += c.byteLength;
	const result = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) {
		result.set(c, offset);
		offset += c.byteLength;
	}
	return result;
}
function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (e) {}
}
async function dohQuery(domain, recordType, targetDoh = DOH_RESOLVER) {
	const cacheKey = `${domain}:${recordType}:${targetDoh}`;
	if (tbDnsCache.has(cacheKey)) {
		const cached = tbDnsCache.get(cacheKey);
		if (Date.now() < cached.expires) return cached.data;
		tbDnsCache.delete(cacheKey);
	}
	try {
		const typeMap = { A: 1, AAAA: 28 };
		const qtype = typeMap[recordType.toUpperCase()] || 1;
		const encodeDomain = (name) => {
			const parts = name.endsWith(".") ? name.slice(0, -1).split(".") : name.split(".");
			const bufs = [];
			for (const label of parts) {
				const enc = TEXT_ENCODER.encode(label);
				bufs.push(new Uint8Array([enc.length]), enc);
			}
			bufs.push(new Uint8Array([0]));
			return concatBytes(...bufs);
		};
		const qname = encodeDomain(domain);
		const query = new Uint8Array(12 + qname.length + 4);
		const qview = new DataView(query.buffer);
		qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]);
		qview.setUint16(2, 0x0100);
		qview.setUint16(4, 1);
		query.set(qname, 12);
		qview.setUint16(12 + qname.length, qtype);
		qview.setUint16(12 + qname.length + 2, 1);
		const response = await fetch(targetDoh, {
			method: "POST",
			headers: {
				"Content-Type": "application/dns-message",
				Accept: "application/dns-message",
			},
			body: query,
		});
		if (!response.ok) return [];
		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4);
		const ancount = dv.getUint16(6);
		const parseName = (pos) => {
			const labels = [];
			let p = pos,
				jumped = false,
				endPos = -1,
				safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) {
					if (!jumped) endPos = p + 1;
					break;
				}
				if ((len & 0xc0) === 0xc0) {
					if (!jumped) endPos = p + 2;
					p = ((len & 0x3f) << 8) | buf[p + 1];
					jumped = true;
					continue;
				}
				labels.push(TEXT_DECODER.decode(buf.slice(p + 1, p + 1 + len)));
				p += len + 1;
			}
			if (endPos === -1) endPos = p + 1;
			return [labels.join("."), endPos];
		};
		let offset = 12;
		for (let i = 0; i < qdcount; i++) {
			const [, end] = parseName(offset);
			offset = Number(end) + 4;
		}
		const answers = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = parseName(offset);
			offset = Number(nameEnd);
			const type = dv.getUint16(offset);
			offset += 2;
			offset += 2;
			const ttl = dv.getUint32(offset);
			offset += 4;
			const rdlen = dv.getUint16(offset);
			offset += 2;
			const rdata = buf.slice(offset, offset + rdlen);
			offset += rdlen;
			let data;
			if (type === 1 && rdlen === 4) {
				data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			} else if (type === 28 && rdlen === 16) {
				const segs = [];
				for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
				data = segs.join(":");
			} else {
				data = Array.from(rdata)
					.map((b) => b.toString(16).padStart(2, "0"))
					.join("");
			}
			answers.push({ name, type, TTL: ttl, data });
		}
		if (tbDnsCache.size >= TB_DNS_MAX) {
			const oldestKey = tbDnsCache.keys().next().value;
			if (oldestKey !== undefined) tbDnsCache.delete(oldestKey);
		}
		tbDnsCache.set(cacheKey, { data: answers, expires: Date.now() + TB_DNS_TTL });
		return answers;
	} catch (e) {
		return [];
	}
}
function createUpstreamQueue({ getWriter, releaseWriter, retryConnect, closeConnection, name = "UpstreamQueue" }) {
	let chunks = [];
	let head = 0;
	let queuedBytes = 0;
	let draining = false;
	let closed = false;
	let bundleBuffer = null;
	let idleResolvers = [];
	let activeCompletions = null;
	const settleCompletions = (completions, err = null) => {
		if (!completions) return;
		for (const comp of completions) {
			if (comp) {
				if (err) comp.reject(err);
				else comp.resolve();
			}
		}
	};
	const rejectQueued = (err) => {
		for (let i = head; i < chunks.length; i++) {
			const item = chunks[i];
			if (item && item.completions) settleCompletions(item.completions, err);
		}
	};
	const compact = () => {
		if (head > 32 && head * 2 >= chunks.length) {
			chunks = chunks.slice(head);
			head = 0;
		}
	};
	const resolveIdle = () => {
		if (queuedBytes || draining || !idleResolvers.length) return;
		const resolvers = idleResolvers;
		idleResolvers = [];
		for (const resolve of resolvers) resolve();
	};
	const clear = (err = null) => {
		const closeErr = err || (closed ? new Error(`${name}: queue closed`) : null);
		if (closeErr) {
			rejectQueued(closeErr);
			settleCompletions(activeCompletions, closeErr);
			activeCompletions = null;
		}
		chunks = [];
		head = 0;
		queuedBytes = 0;
		resolveIdle();
	};
	const shift = () => {
		if (head >= chunks.length) return null;
		const item = chunks[head];
		chunks[head++] = undefined;
		queuedBytes -= item.chunk.byteLength;
		compact();
		return item;
	};
	const bundle = () => {
		const first = shift();
		if (!first) return null;
		if (head >= chunks.length || first.chunk.byteLength >= UPSTREAM_BUNDLE_TARGET_BYTES) return first;
		let byteLength = first.chunk.byteLength;
		let end = head;
		let allowRetry = first.allowRetry;
		let completions = first.completions || null;
		while (end < chunks.length) {
			const next = chunks[end];
			const nextLength = byteLength + next.chunk.byteLength;
			if (nextLength > UPSTREAM_BUNDLE_TARGET_BYTES) break;
			byteLength = nextLength;
			allowRetry = allowRetry && next.allowRetry;
			if (next.completions) completions = completions ? completions.concat(next.completions) : next.completions;
			end++;
		}
		if (end === head) return first;
		const output = (bundleBuffer ||= new Uint8Array(UPSTREAM_BUNDLE_TARGET_BYTES));
		output.set(first.chunk);
		let offset = first.chunk.byteLength;
		while (head < end) {
			const next = chunks[head];
			chunks[head++] = undefined;
			queuedBytes -= next.chunk.byteLength;
			output.set(next.chunk, offset);
			offset += next.chunk.byteLength;
		}
		compact();
		return { chunk: output.subarray(0, byteLength), allowRetry, completions };
	};
	const drain = async () => {
		if (draining || closed) return;
		draining = true;
		try {
			let batchCount = 0;
			for (;;) {
				if (closed) break;
				const item = bundle();
				if (!item) break;
				let writer = getWriter();
				if (!writer) throw new Error(`${name}: remote writer unavailable`);
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					try {
						await writer.write(item.chunk);
					} catch (err) {
						releaseWriter?.();
						if (!item.allowRetry || typeof retryConnect !== "function") throw err;
						await retryConnect();
						writer = getWriter();
						if (!writer) throw err;
						await writer.write(item.chunk);
					}
					settleCompletions(completions);
				} catch (err) {
					settleCompletions(completions, err);
					throw err;
				} finally {
					if (activeCompletions === completions) activeCompletions = null;
				}
				batchCount++;
				if (batchCount >= 16) {
					await Promise.resolve();
					batchCount = 0;
				}
			}
		} catch (err) {
			closed = true;
			clear(err);
			try {
				closeConnection?.(err);
			} catch (_) {}
		} finally {
			draining = false;
			if (!closed && head < chunks.length) queueMicrotask(drain);
			else resolveIdle();
		}
	};
	const enqueue = (data, allowRetry = true, waitForFlush = false) => {
		if (closed) return false;
		if (!getWriter()) return false;
		const chunk = convertToUint8Array(data);
		if (!chunk.byteLength) return true;
		const nextBytes = queuedBytes + chunk.byteLength;
		const nextItems = chunks.length - head + 1;
		if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
			closed = true;
			const err = Object.assign(new Error(`${name}: upload queue overflow`), { isQueueOverflow: true });
			clear(err);
			try {
				closeConnection?.(err);
			} catch (_) {}
			// soft-fail: never throw (prevents Worker 1101 under load)
			if (waitForFlush) return Promise.resolve(false);
			return false;
		}
		let completionPromise = null;
		let completions = null;
		if (waitForFlush) {
			completions = [];
			completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
		}
		chunks.push({ chunk, allowRetry, completions });
		queuedBytes = nextBytes;
		if (!draining) queueMicrotask(drain);
		return waitForFlush ? completionPromise.then(() => true).catch(() => false) : true;
	};
	return {
		async writeAndAwait(data, allowRetry = true) {
			try {
				const r = enqueue(data, allowRetry, true);
				if (r && typeof r.then === "function") return await r;
				return !!r;
			} catch (_) {
				return false;
			}
		},
		async awaitEmpty() {
			if (!queuedBytes && !draining) return;
			await new Promise((resolve) => idleResolvers.push(resolve));
		},
		clear() {
			closed = true;
			clear();
		},
	};
}
function createDownstreamSender(webSocket, headerData = null) {
	const MAX_CAP = 128 * 1024;
	const MIN_CAP = 8 * 1024;
	let currentPacketCap = 32 * 1024;
	const tailBytes = 512;
	let header = headerData;
	let pendingBuffer = null;
	let pendingBytes = 0;
	let flushPromise = null;
	let microtaskQueued = false;
	const adjustSmartBuffer = () => {
		const buffered = webSocket.bufferedAmount || 0;
		if (buffered > 256 * 1024) {
			currentPacketCap = Math.max(MIN_CAP, Math.floor(currentPacketCap / 2));
		} else if (buffered < 32 * 1024) {
			currentPacketCap = Math.min(MAX_CAP, currentPacketCap * 2);
		}
	};
	const sendRawChunk = async (chunk) => {
		if (webSocket.readyState !== 1) return;
		try {
			webSocket.send(chunk);
		} catch (_) {}
	};
	const attachResponseHeader = (chunk) => {
		if (!header) return chunk;
		const merged = new Uint8Array(header.length + chunk.byteLength);
		merged.set(header, 0);
		merged.set(chunk, header.length);
		header = null;
		return merged;
	};
	const flush = async () => {
		microtaskQueued = false;
		while (flushPromise) await flushPromise;
		if (!pendingBytes) return;
		const output = pendingBuffer.slice(0, pendingBytes);
		adjustSmartBuffer();
		pendingBytes = 0;
		flushPromise = sendRawChunk(output).finally(() => {
			flushPromise = null;
		});
		return flushPromise;
	};
	return {
		async sendDirect(data) {
			let chunk = convertToUint8Array(data);
			if (!chunk.byteLength) return;
			chunk = attachResponseHeader(chunk);
			await sendRawChunk(chunk);
		},
		async send(data) {
			let chunk = convertToUint8Array(data);
			if (!chunk.byteLength) return;
			chunk = attachResponseHeader(chunk);
			let offset = 0;
			const totalBytes = chunk.byteLength;
			while (offset < totalBytes) {
				if (!pendingBytes && totalBytes - offset >= currentPacketCap) {
					const sendBytes = Math.min(currentPacketCap, totalBytes - offset);
					const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
					await sendRawChunk(view);
					offset += sendBytes;
					adjustSmartBuffer();
					continue;
				}
				const copyBytes = Math.min(currentPacketCap - pendingBytes, totalBytes - offset);
				if (!pendingBuffer) pendingBuffer = new Uint8Array(MAX_CAP);
				pendingBuffer.set(chunk.subarray(offset, offset + copyBytes), pendingBytes);
				pendingBytes += copyBytes;
				offset += copyBytes;
				if (pendingBytes >= currentPacketCap || currentPacketCap - pendingBytes < tailBytes) {
					await flush();
				} else if (!microtaskQueued) {
					microtaskQueued = true;
					queueMicrotask(() => {
						if (pendingBytes) flush().catch(() => closeSocketQuietly(webSocket));
					});
				}
			}
		},
		flush,
	};
}
async function waitForBackpressure(ws) {
	if (typeof ws.bufferedAmount === "number") {
		let maxAttempts = 300;
		while (ws.bufferedAmount > 512 * 1024 && maxAttempts > 0) {
			if (ws.readyState !== WebSocket.OPEN) break;
			await new Promise((r) => setTimeout(r, 5));
			maxAttempts--;
		}
	}
}
async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, onBytes) {
	let header = headerData,
		hasData = false,
		reader,
		useBYOB = false;
	const BYOB_LIMIT = 128 * 1024;
	const downstreamSender = createDownstreamSender(webSocket, header);
	header = null;
	try {
		reader = remoteSocket.readable.getReader({ mode: "byob" });
		useBYOB = true;
	} catch (e) {
		reader = remoteSocket.readable.getReader();
	}
	try {
		if (!useBYOB) {
			while (true) {
				if (webSocket.bufferedAmount > 512 * 1024) await waitForBackpressure(webSocket);
				const { done, value } = await reader.read();
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (typeof onBytes === "function") onBytes(value.byteLength);
				await downstreamSender.send(value);
			}
		} else {
			let readBuffer = new ArrayBuffer(BYOB_LIMIT);
			while (true) {
				if (webSocket.bufferedAmount > 512 * 1024) await waitForBackpressure(webSocket);
				const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, BYOB_LIMIT));
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (typeof onBytes === "function") onBytes(value.byteLength);
				if (value.byteLength >= DOWNSTREAM_GRAIN_BYTES) {
					await downstreamSender.flush();
					await downstreamSender.sendDirect(value);
					readBuffer = new ArrayBuffer(BYOB_LIMIT);
				} else {
					await downstreamSender.send(value);
					readBuffer = value.buffer.byteLength >= BYOB_LIMIT ? value.buffer : new ArrayBuffer(BYOB_LIMIT);
				}
			}
		}
		await downstreamSender.flush();
	} catch (err) {
		closeSocketQuietly(webSocket);
	} finally {
		try {
			reader.cancel();
		} catch (e) {}
		try {
			reader.releaseLock();
		} catch (e) {}
	}
	if (!hasData && retryFunc) await retryFunc();
}
async function connectDirect(address, port, initialData = null, targetDoh = "https://cloudflare-dns.com/dns-query") {
	const socket = connect({ hostname: address, port: port });
	await Promise.race([socket.opened, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 8000))]);
	if (initialData && initialData.byteLength > 0) {
		const w = socket.writable.getWriter();
		await w.write(convertToUint8Array(initialData));
		w.releaseLock();
	}
	return socket;
}
async function forwardvIeesUDP(udpChunk, webSocket, respHeader, onBytes, dnsServer = "8.8.4.4") {
	const requestData = convertToUint8Array(udpChunk);
	let tcpSocket = null;
	const abortCtl = new AbortController();
	const timeoutId = setTimeout(() => {
		try {
			abortCtl.abort();
		} catch (e) {}
	}, 10000);
	try {
		tcpSocket = connect({ hostname: dnsServer, port: 53 });
		let vIeesHeader = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(requestData);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(
			new WritableStream({
				async write(chunk) {
					const rawResponse = convertToUint8Array(chunk);
					if (typeof onBytes === "function") onBytes(rawResponse.byteLength);
					if (webSocket.readyState !== WebSocket.OPEN) return;
					if (vIeesHeader) {
						const merged = new Uint8Array(vIeesHeader.length + rawResponse.byteLength);
						merged.set(vIeesHeader, 0);
						merged.set(rawResponse, vIeesHeader.length);
						webSocket.send(merged.buffer);
						vIeesHeader = null;
					} else {
						webSocket.send(rawResponse);
					}
				},
			}),
			{ signal: abortCtl.signal },
		);
	} catch (e) {
	} finally {
		clearTimeout(timeoutId);
		try {
			if (tcpSocket) tcpSocket.close();
		} catch (e) {}
	}
}
function extractUUIDFromvIees(data) {
	if (data.byteLength < 17) return null;
	const hex = [...data.slice(1, 17)].map((b) => b.toString(16).padStart(2, "0")).join("");
	return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}
/** SHA-224 helper */
function sha224Hex(message) {
	function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
	function zf(n) {
		const s = "00000000" + (n >>> 0).toString(16);
		return s.slice(-8);
	}
	const K = [
		0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
		0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
		0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
		0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
		0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
		0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
		0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
		0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
	];
	const msg = typeof message === "string" ? TEXT_ENCODER.encode(message) : message;
	const l = msg.length;
	const bitLen = l * 8;
	const totalLen = ((l + 9 + 63) & ~63);
	const buf = new Uint8Array(totalLen);
	buf.set(msg);
	buf[l] = 0x80;
	const dv = new DataView(buf.buffer);
	dv.setUint32(totalLen - 4, bitLen >>> 0, false);
	dv.setUint32(totalLen - 8, Math.floor(bitLen / 0x100000000), false);
	let h0 = 0xc1059ed8, h1 = 0x367cd507, h2 = 0x3070dd17, h3 = 0xf70e5939;
	let h4 = 0xffc00b31, h5 = 0x68581511, h6 = 0x64f98fa7, h7 = 0xbefa4fa4;
	const w = new Uint32Array(64);
	for (let i = 0; i < totalLen; i += 64) {
		for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4, false);
		for (let t = 16; t < 64; t++) {
			const s0 = rotr(w[t-15], 7) ^ rotr(w[t-15], 18) ^ (w[t-15] >>> 3);
			const s1 = rotr(w[t-2], 17) ^ rotr(w[t-2], 19) ^ (w[t-2] >>> 10);
			w[t] = (w[t-16] + s0 + w[t-7] + s1) >>> 0;
		}
		let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
		for (let t = 0; t < 64; t++) {
			const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
			const ch = (e & f) ^ (~e & g);
			const t1 = (h + S1 + ch + K[t] + w[t]) >>> 0;
			const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
			const maj = (a & b) ^ (a & c) ^ (b & c);
			const t2 = (S0 + maj) >>> 0;
			h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
		}
		h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0;
		h4=(h4+e)>>>0; h5=(h5+f)>>>0; h6=(h6+g)>>>0; h7=(h7+h)>>>0;
	}
	return zf(h0)+zf(h1)+zf(h2)+zf(h3)+zf(h4)+zf(h5)+zf(h6);
}
function isLikelyAuthHeader(buf) {
	if (!buf || buf.byteLength < 58) return false;
	if (buf[56] !== 0x0d || buf[57] !== 0x0a) return false;
	for (let i = 0; i < 56; i++) {
		const c = buf[i];
		const isHex = (c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70);
		if (!isHex) return false;
	}
	return true;
}
function parseAuthHeader(buf) {
	if (!isLikelyAuthHeader(buf)) return null;
	const hash = TEXT_DECODER.decode(buf.slice(0, 56)).toLowerCase();
	let offset = 58;
	if (buf.byteLength < offset + 2) return { needMore: true };
	const cmd = buf[offset++];
	const atyp = buf[offset++];
	let addr = "";
	if (atyp === 0x01) {
		if (buf.byteLength < offset + 4 + 2 + 2) return { needMore: true };
		addr = buf[offset++] + "." + buf[offset++] + "." + buf[offset++] + "." + buf[offset++];
	} else if (atyp === 0x03) {
		if (buf.byteLength < offset + 1) return { needMore: true };
		const len = buf[offset++];
		if (buf.byteLength < offset + len + 2 + 2) return { needMore: true };
		addr = TEXT_DECODER.decode(buf.slice(offset, offset + len));
		offset += len;
	} else if (atyp === 0x04) {
		if (buf.byteLength < offset + 16 + 2 + 2) return { needMore: true };
		const parts = [];
		for (let i = 0; i < 8; i++) {
			parts.push(((buf[offset] << 8) | buf[offset + 1]).toString(16));
			offset += 2;
		}
		addr = parts.join(":");
	} else {
		return null;
	}
	if (buf.byteLength < offset + 4) return { needMore: true };
	const port = (buf[offset++] << 8) | buf[offset++];
	if (buf[offset] !== 0x0d || buf[offset + 1] !== 0x0a) return null;
	offset += 2;
	return { hash, cmd, addr, port, payload: buf.slice(offset) };
}
async function fetchCfAccountRequestsToday(env) {
	try {
		const now = new Date();
		const y = now.getUTCFullYear();
		const mo = String(now.getUTCMonth() + 1).padStart(2, "0");
		const da = String(now.getUTCDate()).padStart(2, "0");
		const dayKey = y + "-" + mo + "-" + da;
		if (CF_REQ_CACHE.day && CF_REQ_CACHE.day !== dayKey) {
			CF_REQ_CACHE.day = dayKey;
			CF_REQ_CACHE.base = 0;
			CF_REQ_CACHE.fetchedAt = 0;
			CF_REQ_CACHE.delta = 0;
		}
		CF_REQ_CACHE.day = dayKey;

		const CACHE_MS = 45000;
		const freshEnough = CF_REQ_CACHE.fetchedAt && Date.now() - CF_REQ_CACHE.fetchedAt < CACHE_MS;

		if (!freshEnough) {
			let token = env.CF_API_TOKEN || null;
			let accountId = env.CF_ACCOUNT_ID || null;
			if (!token) {
				try {
					let row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'cf_api_token'").first();
					if (!row || !row.value) row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'cf_token'").first();
					if (row && row.value) token = row.value;
				} catch (e) {}
			}
			if (token) {
				if (!accountId) {
					try {
						const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'cf_account_id'").first();
						if (row && row.value) accountId = row.value;
					} catch (e) {}
				}
				const cfHeaders = {
					Authorization: "Bearer " + token,
					"Content-Type": "application/json",
					"User-Agent": "Mozilla/5.0",
				};
				if (!accountId) {
					try {
						const accRes = await fetch("https://api.cloudflare.com/client/v4/accounts", { headers: cfHeaders });
						const accJson = await accRes.json().catch(function () { return {}; });
						if (accJson.success && accJson.result && accJson.result[0]) accountId = accJson.result[0].id;
					} catch (e) {}
				}
				if (accountId) {
					const startIso = dayKey + "T00:00:00Z";
					const endDt = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1));
					const endIso =
						endDt.getUTCFullYear() +
						"-" +
						String(endDt.getUTCMonth() + 1).padStart(2, "0") +
						"-" +
						String(endDt.getUTCDate()).padStart(2, "0") +
						"T00:00:00Z";

					function sumGroups(groups) {
						let total = 0;
						for (let i = 0; i < (groups || []).length; i++) {
							const sum = groups[i] && groups[i].sum ? groups[i].sum : {};
							total += (Number(sum.requests) || 0) + (Number(sum.subrequests) || 0);
						}
						return total;
					}

					const q =
						'query { viewer { accounts(filter: { accountTag: "' +
						accountId +
						'" }) { workersInvocationsAdaptive(limit: 10000, filter: { datetime_geq: "' +
						startIso +
						'", datetime_lt: "' +
						endIso +
						'" }) { sum { requests subrequests } dimensions { scriptName } } } } }';
					try {
						const gRes = await fetch("https://api.cloudflare.com/client/v4/graphql", {
							method: "POST",
							headers: cfHeaders,
							body: JSON.stringify({ query: q }),
						});
						const gJson = await gRes.json().catch(function () { return {}; });
						let groups =
							gJson &&
							gJson.data &&
							gJson.data.viewer &&
							gJson.data.viewer.accounts &&
							gJson.data.viewer.accounts[0] &&
							gJson.data.viewer.accounts[0].workersInvocationsAdaptive
								? gJson.data.viewer.accounts[0].workersInvocationsAdaptive
								: null;
						if (!groups || (gJson.errors && gJson.errors.length)) {
							const q2 =
								'query { viewer { accounts(filter: { accountTag: "' +
								accountId +
								'" }) { workersInvocationsAdaptive(limit: 10000, filter: { datetime_geq: "' +
								startIso +
								'", datetime_lt: "' +
								endIso +
								'" }) { sum { requests subrequests } } } } }';
							const gRes2 = await fetch("https://api.cloudflare.com/client/v4/graphql", {
								method: "POST",
								headers: cfHeaders,
								body: JSON.stringify({ query: q2 }),
							});
							const gJson2 = await gRes2.json().catch(function () { return {}; });
							groups =
								gJson2 &&
								gJson2.data &&
								gJson2.data.viewer &&
								gJson2.data.viewer.accounts &&
								gJson2.data.viewer.accounts[0] &&
								gJson2.data.viewer.accounts[0].workersInvocationsAdaptive
									? gJson2.data.viewer.accounts[0].workersInvocationsAdaptive
									: [];
						}
						const live = sumGroups(groups);
						const localNow = (CF_REQ_CACHE.base || 0) + (CF_REQ_CACHE.delta || 0);
						CF_REQ_CACHE.base = Math.max(live, localNow);
						CF_REQ_CACHE.delta = 0;
						CF_REQ_CACHE.fetchedAt = Date.now();
					} catch (e) {}
				}
			}
		}

		const today = (CF_REQ_CACHE.base || 0) + (CF_REQ_CACHE.delta || 0);
		return { today: today, limit: 100000 };
	} catch (e) {
		const today = (CF_REQ_CACHE.base || 0) + (CF_REQ_CACHE.delta || 0);
		return { today: today, limit: 100000 };
	}
}

function trackRequest(env, ctx) {
	tbReqTotal++;
	CF_REQ_CACHE.delta = (CF_REQ_CACHE.delta || 0) + 1;
	const now = Date.now();
	if ((now - tbLastReqWrite > 900000 || tbReqTotal > 5000) && tbReqTotal > 0) {
		tbLastReqWrite = now;
		const countToSave = tbReqTotal;
		tbReqTotal = 0;
		const task = async () => {
			try {
				const today = new Date().toISOString().split("T")[0];
				await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_total', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?").bind(String(countToSave), String(countToSave)).run();
				const lastDateRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_last_date'").first();
				if (!lastDateRow || lastDateRow.value !== today) {
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_last_date', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(today, today).run();
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(countToSave), String(countToSave)).run();
				} else {
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?").bind(String(countToSave), String(countToSave)).run();
				}
			} catch (e) {}
		};
		if (ctx) ctx.waitUntil(task());
		else task();
	}
}
async function connectProxy(proxyStr, destAddr, destPort, initialData) {
	let normalized = proxyStr;
	if (proxyStr.includes("t.me/socks") || proxyStr.includes("tg://socks")) {
		const server = proxyStr.match(/server=([^&]+)/)?.[1];
		const port = proxyStr.match(/port=([^&]+)/)?.[1];
		const user = proxyStr.match(/user=([^&]+)/)?.[1];
		const pass = proxyStr.match(/pass=([^&]+)/)?.[1];
		if (server && port) {
			normalized = user && pass ? `socks5://${user}:${pass}@${server}:${port}` : `socks5://${server}:${port}`;
		}
	}
	const isHttp = normalized.toLowerCase().startsWith("http://") || normalized.toLowerCase().startsWith("https://");
	const isSocks4 = normalized.toLowerCase().startsWith("socks4://");
	let cleanStr = normalized.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
	if (isHttp) {
		return await connectHttp(cleanStr, destAddr, destPort, initialData);
	}
	if (isSocks4) {
		return await connectSocks4(cleanStr, destAddr, destPort, initialData);
	}
	return await connectSocks5(cleanStr, destAddr, destPort, initialData);
}
async function connectSocks4(proxyStr, destAddr, destPort, initialData) {
	const { user, pass, host, port, auth } = parseProxyConfig(proxyStr, 1080);
	const socket = connect({ hostname: host, port: port });
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();
	try {
		const portHigh = (destPort >> 8) & 0xff;
		const portLow = destPort & 0xff;
		let req;
		if (isIPv4(destAddr)) {
			const ipBytes = destAddr.split(".").map(Number);
			req = new Uint8Array([0x04, 0x01, portHigh, portLow, ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3], 0x00]);
		} else {
			const hostBytes = new TextEncoder().encode(destAddr);
			req = new Uint8Array(9 + hostBytes.length + 1);
			req[0] = 0x04;
			req[1] = 0x01;
			req[2] = portHigh;
			req[3] = portLow;
			req[4] = 0x00;
			req[5] = 0x00;
			req[6] = 0x00;
			req[7] = 0x01;
			req[8] = 0x00;
			req.set(hostBytes, 9);
			req[9 + hostBytes.length] = 0x00;
		}
		await writer.write(req);
		let res = await reader.read();
		if (res.done || !res.value || res.value[0] !== 0x00 || res.value[1] !== 0x5a) {
			throw new Error("SOCKS4 proxy failed to connect or rejected the connection");
		}
		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}
		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try {
			writer.releaseLock();
		} catch (err) {}
		try {
			reader.releaseLock();
		} catch (err) {}
		try {
			socket.close();
		} catch (err) {}
		throw e;
	}
}
function parseProxyConfig(proxyStr, defaultPort) {
	let user = "",
		pass = "",
		host = "",
		port = defaultPort;
	let auth = false,
		remain = proxyStr;
	if (remain.includes("@")) {
		const atIdx = remain.lastIndexOf("@");
		const authPart = remain.substring(0, atIdx);
		remain = remain.substring(atIdx + 1);
		const colonIdx = authPart.indexOf(":");
		if (colonIdx !== -1) {
			user = authPart.substring(0, colonIdx);
			pass = authPart.substring(colonIdx + 1);
		} else {
			user = authPart;
		}
		auth = true;
	}
	if (remain.startsWith("[")) {
		const closeIdx = remain.indexOf("]");
		if (closeIdx !== -1) {
			host = remain.substring(1, closeIdx);
			if (remain.length > closeIdx + 1 && remain[closeIdx + 1] === ":") port = parseInt(remain.substring(closeIdx + 2)) || defaultPort;
		}
	} else {
		const lastColon = remain.lastIndexOf(":");
		if (lastColon !== -1 && remain.indexOf(":") === lastColon) {
			host = remain.substring(0, lastColon);
			port = parseInt(remain.substring(lastColon + 1)) || defaultPort;
		} else {
			host = remain;
		}
	}
	return { user, pass, host, port, auth };
}
async function connectSocks5(socksStr, destAddr, destPort, initialData) {
	const { user, pass, host, port, auth } = parseProxyConfig(socksStr, 1080);
	const socket = connect({ hostname: host, port: port });
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();
	try {
		if (auth) {
			await writer.write(new Uint8Array([0x05, 0x02, 0x00, 0x02]));
		} else {
			await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
		}
		let res = await reader.read();
		if (res.done || !res.value || res.value[0] !== 0x05) throw new Error("Invalid response (not a SOCKS5 proxy or offline)");
		const method = res.value[1];
		if (method === 0x02) {
			const uEnc = new TextEncoder().encode(user);
			const pEnc = new TextEncoder().encode(pass);
			const authReq = new Uint8Array(1 + 1 + uEnc.length + 1 + pEnc.length);
			authReq[0] = 0x01;
			authReq[1] = uEnc.length;
			authReq.set(uEnc, 2);
			authReq[2 + uEnc.length] = pEnc.length;
			authReq.set(pEnc, 3 + uEnc.length);
			await writer.write(authReq);
			let authRes = await reader.read();
			if (authRes.done || !authRes.value || authRes.value[1] !== 0x00) throw new Error("Proxy username or password is incorrect");
		}
		let addrType = 0x03;
		let addrBytes;
		if (isIPv4(destAddr)) {
			addrType = 0x01;
			addrBytes = new Uint8Array(destAddr.split(".").map(Number));
		} else if (destAddr.includes(":")) {
			addrType = 0x04;
			addrBytes = new Uint8Array(16);
			const blocks = destAddr.split(":");
			for (let i = 0; i < 8; i++) {
				const val = parseInt(blocks[i] || "0", 16);
				addrBytes[i * 2] = (val >> 8) & 0xff;
				addrBytes[i * 2 + 1] = val & 0xff;
			}
		} else {
			const enc = new TextEncoder().encode(destAddr);
			addrBytes = new Uint8Array(1 + enc.length);
			addrBytes[0] = enc.length;
			addrBytes.set(enc, 1);
		}
		const req = new Uint8Array(4 + addrBytes.length + 2);
		req[0] = 0x05;
		req[1] = 0x01;
		req[2] = 0x00;
		req[3] = addrType;
		req.set(addrBytes, 4);
		const portOffset = 4 + addrBytes.length;
		req[portOffset] = (destPort >> 8) & 0xff;
		req[portOffset + 1] = destPort & 0xff;
		await writer.write(req);
		let connRes = await reader.read();
		if (connRes.done || !connRes.value || connRes.value[1] !== 0x00) throw new Error("Proxy connected but has no open internet access");
		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}
		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try {
			writer.releaseLock();
		} catch (err) {}
		try {
			reader.releaseLock();
		} catch (err) {}
		try {
			socket.close();
		} catch (err) {}
		throw e;
	}
}
async function connectHttp(proxyStr, destAddr, destPort, initialData) {
	const { user, pass, host, port, auth } = parseProxyConfig(proxyStr, 80);
	const socket = connect({ hostname: host, port: port });
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();
	try {
		const safeDest = destAddr.includes(":") ? `[${destAddr}]` : destAddr;
		let req = `CONNECT ${safeDest}:${destPort} HTTP/1.1\r\nHost: ${safeDest}:${destPort}\r\n`;
		if (auth) {
			const authBase64 = btoa(`${user}:${pass}`);
			req += `Proxy-Authorization: Basic ${authBase64}\r\n`;
		}
		req += "\r\n";
		await writer.write(new TextEncoder().encode(req));
		let resStr = "";
		const dec = new TextDecoder();
		while (true) {
			const res = await reader.read();
			if (res.done || !res.value) throw new Error("proxy_closed");
			resStr += dec.decode(res.value, { stream: true });
			if (resStr.includes("\r\n\r\n")) {
				const match = resStr.match(/^HTTP\/\d\.\d\s+(\d+)/);
				if (match && match[1] === "200") {
					break;
				} else {
					throw new Error("proxy_error_" + (match ? match[1] : "unknown"));
				}
			}
		}
		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}
		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try {
			writer.releaseLock();
		} catch (err) {}
		try {
			reader.releaseLock();
		} catch (err) {}
		try {
			socket.close();
		} catch (err) {}
		throw e;
	}
}
const HTML_TEMPLATES = {
	nginx: `<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>TrexBridge</title>
<link rel="icon" type="image/jpeg" href="https://i.imgur.com/npyD6Wr.jpeg">
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700;800;900&family=Public+Sans:wght@600;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #f5f0e8; --card: #fffdf5; --ink: #0a0a0a; --muted: #71717a;
    --green: #22c55e; --yellow: #facc15; --violet: #c4b5fd;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    padding: 20px 14px; font-family: "Public Sans", system-ui, sans-serif; font-weight: 700;
    color: var(--ink); background: var(--bg);
  }
  .grid-bg { position:fixed; inset:-20px; z-index:0; pointer-events:none; background-color:#f5f0e8;
      background-image:linear-gradient(to right,rgba(0,0,0,.11) 1.5px,transparent 1.5px),linear-gradient(to bottom,rgba(0,0,0,.11) 1.5px,transparent 1.5px);
      background-size:40px 40px; background-position:-12px -12px; animation:gridDrift 23s ease-in-out infinite alternate; }
  .card {
    width: 100%; max-width: 420px; background: var(--card);
    border: 3.5px solid #000; box-shadow: 6px 6px 0 #000;
    padding: 1.7rem 1.35rem 1.4rem;
    animation: cardPop .55s cubic-bezier(.34,1.56,.64,1) both;
  }
  @keyframes cardPop {
    from { opacity: 0; transform: scale(.94) translateY(16px); }
    to { opacity: 1; transform: scale(1) translateY(0); }
  }
  .brand-wrap { text-align: center; margin-bottom: 1.25rem; }
  .brand {
    display: inline-flex; align-items: center; font-family: Archivo, sans-serif;
    font-weight: 900; font-size: 1.55rem; letter-spacing: -0.03em;
  }
  .brand-box {
    position: relative; overflow: hidden; background: var(--green);
    padding: 4px 12px; border: 2.5px solid #000; box-shadow: 3px 3px 0 #000;
  }
  .brand-box::after {
    content: ""; position: absolute; top: 0; bottom: 0; left: -60%; width: 40%;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,.45), transparent);
    transform: skewX(-18deg); animation: shine 3.8s ease-in-out infinite;
  }
  @keyframes shine { 0%{left:-60%} 100%{left:130%} }
  .brand-bridge { padding-left: 9px; }
  .subtitle {
    margin-top: 10px; font-size: .82rem; font-weight: 800; color: var(--muted);
  }
  .path-tag {
    display: inline-block; margin: 1rem 0 1.2rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-weight: 900; font-size: 1.05rem;
    background: #fff; border: 3px solid #000; box-shadow: 3px 3px 0 #000;
    padding: 8px 16px; letter-spacing: .04em;
  }
  .btn-main {
    background: #a78bfa;
    color: #000;
    width: 100%; min-height: 52px; border: 3px solid #000; background: var(--yellow);
    box-shadow: 4px 4px 0 #000; font-family: inherit; font-weight: 900; font-size: .95rem;
    cursor: pointer; display: flex; align-items: center; justify-content: center;
    text-decoration: none; color: #000;
  }
  .btn-main:hover { transform: translate(-1px,-1px); box-shadow: 5px 5px 0 #000; }
  .btn-main:active { transform: translate(2px,2px); box-shadow: 2px 2px 0 #000; }
  .social-row { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 12px; }
  .btn-sec {
    min-height: 42px; border: 2.5px solid #000; box-shadow: 2px 2px 0 #000;
    display: flex; align-items: center; justify-content: center; gap: 6px;
    font-weight: 800; font-size: .78rem; text-decoration: none; color: #000;
  }
  .btn-tg { background: #38bdf8; color: #000 !important; }
  .btn-gh { background: #a78bfa; color: #000 !important; }
  .foot {
    margin-top: 1rem; text-align: center; font-size: .72rem; font-weight: 700; color: var(--muted);
  }
</style>
</head>
<body>
<div class="grid-bg"></div>
<div class="card">
  <div class="brand-wrap">
    <div class="brand"><span class="brand-box">Trex</span><span class="brand-bridge">Bridge</span></div>
    <p class="subtitle">Open the path below to access the panel</p>
  </div>
  <div style="text-align:center"><span class="path-tag">/app</span></div>
  <a class="btn-main" href="/app">Open panel</a>
  <div class="social-row">
    <a class="btn-sec btn-tg" href="https://t.me/TrexBridgePanel" target="_blank" rel="noopener">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
      Support
    </a>
    <a class="btn-sec btn-gh" href="https://github.com/icubaby/TrexBridge" target="_blank" rel="noopener">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/></svg>
      GitHub
    </a>
  </div>
  <div class="foot">TrexBridge</div>
</div>
</body>
</html>`,
setup: `<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>TrexBridge — Setup</title>
<link rel="icon" type="image/jpeg" href="https://i.imgur.com/npyD6Wr.jpeg">
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@700;800&family=Public+Sans:wght@600;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --black: #0a0a0a;
    --white: #ffffff;
    --green: #22c55e;
    --lime: #bef264;
    --yellow: #facc15;
    --red: #ef4444;
    --muted: #52525b;
    --bg: #d9f99d;
    --card: #ecfccb;
    --border: 3.5px solid var(--black);
    --shadow: 5px 5px 0 var(--black);
    --shadow-sm: 3px 3px 0 var(--black);
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: "Public Sans", system-ui, -apple-system, sans-serif;font-weight:700;
    font-weight: 800;
    background-color: var(--bg);
    background-image:
      linear-gradient(rgba(0,0,0,0.06) 1.5px, transparent 1.5px),
      linear-gradient(90deg, rgba(0,0,0,0.06) 1.5px, transparent 1.5px);
    background-size: 24px 24px;
    color: var(--black);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 16px 12px;
    line-height: 1.4;
    direction: ltr;
  }

  .card {
    width: 100%;
    max-width: 400px;
    background: var(--card);
    border: var(--border);
    box-shadow: var(--shadow);
    padding: 1.75rem 1.4rem 1.5rem;
    animation: cardPop 0.55s cubic-bezier(0.34, 1.56, 0.64, 1) both;
  }

  @keyframes cardPop {
    0% { opacity: 0; transform: scale(0.94) translateY(18px); }
    100% { opacity: 1; transform: scale(1) translateY(0); }
  }

  .brand-wrap {
    text-align: center;
    margin-bottom: 1.5rem;
  }

  .brand {
    display: inline-flex;
    align-items: center;
    font-size: 1.65rem;
    font-weight: 900;
    letter-spacing: -0.6px;
  }

  .brand-trex {
    background: var(--green);
    padding: 4px 12px;
    border: 2.5px solid var(--black);
    box-shadow: 3px 3px 0 var(--black);
  }

  .brand-trex,.brand-bridge,.brand-title .bridge,.brand-title .trex,.brand .t,.brand .ver{
    position:relative;overflow:hidden;
  }
  .brand-trex::after,.brand-title .bridge::after,.brand .t::after{
    content:"";position:absolute;top:0;bottom:0;left:-40%;width:35%;
    background:linear-gradient(90deg,transparent,rgba(255,255,255,.55),transparent);
    transform:skewX(-18deg);pointer-events:none;animation:brandShine 5s ease-in-out infinite;
  }
  @keyframes brandShine{
    0%,62%{left:-40%;opacity:0;}
    64%{opacity:1;}
    86%{left:120%;opacity:1;}
    88%,100%{left:120%;opacity:0;}
  }
  body{
    background-image:
      linear-gradient(rgba(0,0,0,0.06) 1.5px, transparent 1.5px),
      linear-gradient(90deg, rgba(0,0,0,0.06) 1.5px, transparent 1.5px);
    background-size: 24px 24px;
    background-attachment:fixed !important;
  }


  .brand-bridge {
    padding-left: 9px;
  }

  .subtitle {
    margin-top: 12px;
    font-size: 0.82rem;
    font-weight: 800;
    color: var(--muted);
    letter-spacing: 0.2px;
  }

  .form-group {
    margin-bottom: 1.1rem;
  }

  .form-label {
    display: block;
    font-size: 0.72rem;
    font-weight: 800;
    margin-bottom: 7px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.4px;
  }

  .form-input {
    width: 100%;
    padding: 0.8rem 1rem;
    border: 3px solid var(--black);
    background: var(--white);
    box-shadow: 3px 3px 0 var(--black);
    font-family: inherit;
    font-size: 0.95rem;
    font-weight: 700;
    color: var(--black);
    outline: none;
    transition: box-shadow 0.12s ease, transform 0.12s ease;
  }

  .form-input:focus {
    box-shadow: 5px 5px 0 var(--black);
    transform: translate(-1px, -1px);
  }

  .form-input::placeholder {
    color: #a1a1aa;
    font-weight: 700;
  }

  .input-wrap {
    position: relative;
  }

  .input-wrap .form-input {
    padding-right: 50px;
  }

  .toggle-pass {
    position: absolute;
    right: 7px;
    top: 50%;
    transform: translateY(-50%);
    width: 36px;
    height: 36px;
    border: 2.5px solid var(--black);
    background: var(--white);
    box-shadow: 2px 2px 0 var(--black);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: background 0.12s ease, box-shadow 0.12s ease;
  }

  .toggle-pass:hover {
    background: var(--lime);
    box-shadow: 3px 3px 0 var(--black);
  }

  .toggle-pass:active {
    transform: translateY(-50%) translate(1px, 1px);
    box-shadow: 1px 1px 0 var(--black);
  }

  .error-box {
    display: none;
    padding: 0.7rem 0.95rem;
    border: 3px solid var(--black);
    background: #fecaca;
    box-shadow: 3px 3px 0 var(--black);
    font-size: 0.8rem;
    font-weight: 800;
    margin-bottom: 1.1rem;
  }

  .error-box.show {
    display: block;
  }

  .btn-setup {
    width: 100%;
    min-height: 54px;
    margin-top: 0.35rem;
    padding: 0.8rem 1rem;
    border: 3px solid var(--black);
    background: var(--yellow);
    box-shadow: 4px 4px 0 var(--black);
    font-family: inherit;
    font-size: 0.95rem;
    font-weight: 900;
    color: var(--black);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    transition: transform 0.12s ease, box-shadow 0.12s ease, background 0.12s ease;
  }

  .btn-setup:hover:not(:disabled) {
    background: #fde047;
    transform: translate(-1px, -1px);
    box-shadow: 5px 5px 0 var(--black);
  }

  .btn-setup:active:not(:disabled) {
    transform: translate(2px, 2px);
    box-shadow: 2px 2px 0 var(--black);
  }

  .btn-setup:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none;
  }

  .btn-setup .spinner {
    display: none;
    width: 18px;
    height: 18px;
    animation: spin 0.7s linear infinite;
  }

  .btn-setup.loading .spinner { display: block; }
  .btn-setup.loading .btn-text { display: none; }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .social-row {
    display: flex;
    gap: 8px;
    margin-top: 10px;
  }

  .btn-social {
    flex: 1;
    min-height: 42px;
    padding: 0.5rem 0.6rem;
    border: 3px solid var(--black);
    box-shadow: 3px 3px 0 var(--black);
    font-family: inherit;
    font-size: 0.78rem;
    font-weight: 800;
    color: var(--black);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    text-decoration: none;
    transition: transform 0.12s ease, box-shadow 0.12s ease, background 0.12s ease;
  }

  .btn-social:hover {
    transform: translate(-1px, -1px);
    box-shadow: 4px 4px 0 var(--black);
  }

  .btn-social:active {
    transform: translate(2px, 2px);
    box-shadow: 1px 1px 0 var(--black);
  }

  .btn-tg { background: #38bdf8; color: #000 !important; }
  .btn-gh { background: #a78bfa; color: #000 !important; }

  .footer {
    margin-top: 1.45rem;
    text-align: center;
    font-size: 0.7rem;
    font-weight: 800;
    color: var(--muted);
  }

  @media (max-width: 420px) {
    .card { padding: 1.4rem 1.1rem 1.3rem; }
    .brand { font-size: 1.45rem; }
  }

  #toast-wrap{position:fixed;bottom:24px;left:0;right:0;transform:none!important;z-index:9999;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;gap:8px;padding:0 12px;box-sizing:border-box;width:100%;pointer-events:none;}
  .toast{
    position:relative;overflow:hidden;
    background:#fff;border:3px solid #000;box-shadow:4px 4px 0 #000;
    padding:.85rem 1.15rem .75rem 1rem;font-weight:800;font-size:.88rem;color:#000;
    display:flex;align-items:center;gap:10px;min-width:min(280px,90vw);
    transform:translateY(16px);opacity:0;transition:transform .28s cubic-bezier(.34,1.56,.64,1),opacity .22s ease;
  }
  .toast::before{content:"";position:absolute;top:0;left:0;right:0;height:5px;border-bottom:2px solid #000;background:var(--lime,#22c55e);}
  .toast.err::before{background:var(--red,#ef4444);}
  .toast .toast-ico{width:32px;height:32px;flex-shrink:0;border:2.5px solid #000;background:var(--yellow,#facc15);display:inline-flex;align-items:center;justify-content:center;box-shadow:2px 2px 0 #000;}
  .toast.err .toast-ico{background:#fecaca;}
  .toast .toast-ico svg{width:16px;height:16px;display:block;}
  .toast .toast-msg{flex:1;line-height:1.35;font-weight:800;}
  .toast.show{transform:translateY(0);opacity:1;}
  .toast.err{background:#fff5f5;}
  .error-box{display:none!important;}
</style>
</head>
<body>
<div id="toast-wrap"></div>

<div class="card">
  <div class="brand-wrap">
    <div class="brand">
      <span class="brand-trex">Trex</span>
      <span class="brand-bridge">Bridge</span>
    </div>
    <p class="subtitle">Initial setup — choose a panel password</p>
  </div>

  <div class="error-box" id="errorBox"></div>

  <form id="setupForm" autocomplete="off">
    <div class="form-group">
      <label class="form-label" for="pw1">Password</label>
      <div class="input-wrap">
        <input
          class="form-input"
          type="password"
          id="pw1"
          name="password"
          required
          minlength="4"
          placeholder="At least 4 characters"
          autocomplete="new-password"
        />
        <button type="button" class="toggle-pass" id="togglePass1" title="Show password" aria-label="Show password">
          <svg id="eyeIcon1" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
            <circle cx="12" cy="12" r="3"/>
          </svg>
        </button>
      </div>
    </div>

    <div class="form-group">
      <label class="form-label" for="pw2">Confirm password</label>
      <div class="input-wrap">
        <input
          class="form-input"
          type="password"
          id="pw2"
          name="confirm"
          required
          minlength="4"
          placeholder="Confirm password"
          autocomplete="new-password"
        />
        <button type="button" class="toggle-pass" id="togglePass2" title="Show password" aria-label="Show password">
          <svg id="eyeIcon2" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
            <circle cx="12" cy="12" r="3"/>
          </svg>
        </button>
      </div>
    </div>

    <button type="submit" class="btn-setup" id="setupBtn">
      <svg class="spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <circle cx="12" cy="12" r="10" stroke-opacity="0.25"/>
        <path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"/>
      </svg>
      <span class="btn-text">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px;margin-right:4px;">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="M9 12l2 2 4-4"/>
        </svg>
        Save &amp; continue
      </span>
    </button>
  </form>

  <div class="social-row">
    <a href="https://t.me/TrexBridgePanel" class="btn-social btn-tg" target="_blank" rel="noopener">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
      </svg>
      Support
    </a>
    <a href="https://github.com/icubaby/TrexBridge" class="btn-social btn-gh" target="_blank" rel="noopener">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/>
      </svg>
      GitHub
    </a>
  </div>

  <div class="footer">TrexBridge · First-time setup</div>
</div>

<script>
  function toast(msg, isErr){
    var wrap = document.getElementById('toast-wrap');
    if(!wrap){
      wrap = document.createElement('div');
      wrap.id = 'toast-wrap';
      document.body.appendChild(wrap);
    }
    wrap.style.cssText = 'position:fixed;left:0;right:0;bottom:24px;z-index:9999;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;gap:8px;pointer-events:none;padding:0 12px;box-sizing:border-box;width:100%;transform:none;';
    while (wrap.children.length >= 5) {
      try { wrap.removeChild(wrap.firstChild); } catch (e) { break; }
    }
    var el = document.createElement('div');
    el.className = 'toast' + (isErr ? ' err' : '');
    el.innerHTML = '<span class="toast-ico"><svg viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/></svg></span><span class="toast-msg"></span>';
    el.querySelector('.toast-msg').textContent = msg;
    wrap.appendChild(el);
    function paint(){
      var kids = wrap.children, n = kids.length;
      for (var i = 0; i < n; i++) {
        var age = n - 1 - i;
        var op = 1 - age * 0.16;
        if (op < 0.32) op = 0.32;
        if (kids[i].classList.contains('show')) kids[i].style.opacity = String(op);
      }
    }
    requestAnimationFrame(function(){ el.classList.add('show'); paint(); });
    setTimeout(function(){
      el.classList.remove('show');
      el.style.opacity = '0';
      setTimeout(function(){ try{el.remove();}catch(e){} paint(); }, 300);
    }, 2800);
  }

  function bindToggle(inputId, btnId, iconId) {
    var input = document.getElementById(inputId);
    var btn = document.getElementById(btnId);
    var icon = document.getElementById(iconId);
    var showing = false;
    btn.addEventListener('click', function() {
      showing = !showing;
      input.type = showing ? 'text' : 'password';
      if (showing) {
        icon.innerHTML = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>';
      } else {
        icon.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
      }
    });
  }
  bindToggle('pw1', 'togglePass1', 'eyeIcon1');
  bindToggle('pw2', 'togglePass2', 'eyeIcon2');

  document.getElementById('setupForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    var p1 = document.getElementById('pw1').value;
    var p2 = document.getElementById('pw2').value;
    var err = document.getElementById('errorBox');
    var btn = document.getElementById('setupBtn');
    err.textContent = '';

    if (p1.length < 4) {
      err.textContent = 'Password must be at least 4 characters';
      toast('Password must be at least 4 characters', true);
      return;
    }
    if (p1 !== p2) {
      err.textContent = 'Passwords do not match';
      toast('Passwords do not match', true);
      return;
    }

    btn.classList.add('loading');
    btn.disabled = true;

    try {
      var res = await fetch('/api/setup-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: p1 })
      });
      var data = await res.json().catch(function() { return {}; });
      if (res.ok) {
        location.href = '/app';
        return;
      }
      err.textContent = data.error || 'Failed to save password';
      toast(data.error || 'Failed to save password', true);
    } catch (ex) {
      err.textContent = 'Server connection error';
      toast('Server connection error', true);
    } finally {
      btn.classList.remove('loading');
      btn.disabled = false;
    }
  });
</script>
</body>
</html>`,

	login: `<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>TrexBridge — Login</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700;800;900&family=Public+Sans:wght@600;700;800&display=swap" rel="stylesheet">
<style>
  :root { --bg:#f5f0e8; --card:#fffdf5; --ink:#0a0a0a; --muted:#71717a; --green:#22c55e; --yellow:#facc15; --violet:#7c3aed; --sky:#fcd34d; }
  * { box-sizing:border-box; margin:0; padding:0; border-radius:0 !important; }
  body { font-family:"Public Sans",system-ui,sans-serif; font-weight:700; background:var(--bg); color:var(--ink); min-height:100vh; display:flex; align-items:center; justify-content:center; padding:16px 12px; }
  .grid-bg { position:fixed; inset:-20px; z-index:0; pointer-events:none; background-color:#f5f0e8;
      background-image:linear-gradient(to right,rgba(0,0,0,.11) 1.5px,transparent 1.5px),linear-gradient(to bottom,rgba(0,0,0,.11) 1.5px,transparent 1.5px);
      background-size:40px 40px; background-position:-12px -12px; }
  .card { position:relative; z-index:1; width:100%; max-width:400px; background:var(--card); border:3.5px solid #000; box-shadow:6px 6px 0 #000; padding:1.75rem 1.4rem 1.5rem; }
  .brand-wrap { text-align:center; margin-bottom:1.35rem; }
  .brand { display:inline-flex; align-items:center; font-family:Archivo,sans-serif; font-size:1.65rem; font-weight:900; letter-spacing:-0.6px; }
  .brand-box { position:relative; overflow:hidden; background:var(--green); padding:4px 12px; border:2.5px solid #000; box-shadow:3px 3px 0 #000; }
  .brand-box::after { content:""; position:absolute; top:0; bottom:0; left:-60%; width:40%; background:linear-gradient(90deg,transparent,rgba(255,255,255,.45),transparent); transform:skewX(-18deg); animation:shine 3.8s ease-in-out infinite; }
  @keyframes shine { 0%{left:-60%} 100%{left:130%} }
  .brand-bridge { padding-left:9px; }
  .subtitle { margin-top:10px; font-size:.82rem; font-weight:800; color:var(--muted); }
  .field-label { display:block; font-size:11px; font-weight:800; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin-bottom:8px; }
  .form-group { margin-bottom:1rem; }
  .neo-input { width:100%; background:#fffef8 !important; border:2.5px solid #000 !important; box-shadow:3px 3px 0 #000 !important; padding:12px 14px; font-family:inherit; font-weight:700; font-size:15px; outline:none; }
  .neo-input:focus { background:#fff !important; box-shadow:5px 5px 0 #000 !important; }
  .input-wrap { position:relative; }
  .input-wrap .neo-input { padding-right:48px; }
  .toggle-pass {
    position: absolute; right: 7px; top: 50%; transform: translateY(-50%);
    width: 36px; height: 36px; border: 2.5px solid #000; background: #fff;
    box-shadow: 2px 2px 0 #000; cursor: pointer;
    display: flex; align-items: center; justify-content: center;
    transition: background .12s ease, box-shadow .12s ease;
  }
  .toggle-pass:hover { background: #facc15; }
  .toggle-pass:active { transform: translateY(-50%) translate(1px,1px); box-shadow: 1px 1px 0 #000; }
.error-box { display:none; padding:.7rem .95rem; border:3px solid #000; background:#fecaca; box-shadow:3px 3px 0 #000; font-size:.8rem; font-weight:800; margin-bottom:1.1rem; }
  .error-box.show { display:block; }
  .ok-box { display:none; padding:.7rem .95rem; border:3px solid #000; background:#bbf7d0; box-shadow:3px 3px 0 #000; font-size:.8rem; font-weight:800; margin-bottom:1.1rem; }
  .ok-box.show { display:block; }
  .btn-main { width:100%; min-height:52px; border:3px solid #000; background:#a78bfa; color:#000 !important; box-shadow:4px 4px 0 #000; font-family:inherit; font-weight:900; font-size:.95rem; cursor:pointer; display:flex; align-items:center; justify-content:center; gap:8px; }
  .btn-main:hover { transform:translate(-2px,-2px); box-shadow:6px 6px 0 #000; }
  .btn-main:disabled { opacity:.6; cursor:wait; }
  .btn-yellow { background:var(--yellow); }
  .btn-sky { background:var(--sky); }
  .btn-forgot {
    width: 100%; margin-top: 10px; min-height: 42px; border: 2.5px solid #000;
    background: #f9a8d4; color: #000 !important; box-shadow: 3px 3px 0 #000; font-family: inherit; font-weight: 900;
    font-size: .85rem; cursor: pointer;
  }
  .btn-forgot {
    width: 100%; margin-top: 10px; min-height: 42px; border: 2.5px solid #000;
    background: #f9a8d4; color: #000 !important; box-shadow: 3px 3px 0 #000; font-family: inherit; font-weight: 900;
    font-size: .85rem; cursor: pointer;
  }
  .btn-forgot:active { transform: translate(1px,1px); box-shadow: 2px 2px 0 #000; }
  .social-row { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 12px; }
  .btn-sec {
    min-height: 42px; border: 2.5px solid #000; box-shadow: 2px 2px 0 #000;
    display: flex; align-items: center; justify-content: center; gap: 6px;
    font-weight: 800; font-size: .78rem; text-decoration: none; color: #000;
  }
  .btn-tg { background: #38bdf8; color: #000 !important; }
  .btn-gh { background: #a78bfa; color: #000 !important; }
  .btn-link { background:none; border:none; cursor:pointer; font-family:inherit; font-size:11px; font-weight:800; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; width:100%; text-align:center; margin-top:1rem; padding-top:1rem; border-top:3px solid #000; }
  .btn-back { background:#fde68a; border:2.5px solid #000; cursor:pointer; font-family:inherit; font-size:13px; font-weight:800; color:#000; margin-bottom:12px; display:inline-flex; align-items:center; gap:6px; padding:8px 14px; box-shadow:2px 2px 0 #000; }
  .btn-back:active { transform:translate(1px,1px); box-shadow:1px 1px 0 #000; }
  .footer { margin-top:1rem; text-align:center; font-size:.68rem; font-weight:700; color:var(--muted); }
  .step-hint { font-size:14px; font-weight:900; color:#000; margin-bottom:14px; line-height:1.45; }
  .field-label-box { display:inline-block; font-size:11px; font-weight:800; text-transform:uppercase; letter-spacing:.06em; color:#000; margin-bottom:8px; padding:4px 10px; border:2.5px solid #000; box-shadow:2px 2px 0 #000; }
  .fl-user { background:#7dd3fc; }
  .fl-pass { background:#facc15; }
  .fl-token { background:#a78bfa; }
  .fl-newuser { background:#86efac; }
  .fl-newpass { background:#fdba74; }
  .fl-confirm { background:#f9a8d4; }
  #toast-wrap { position:fixed; left:0; right:0; bottom:24px; z-index:9999; display:flex; flex-direction:column; align-items:center; gap:8px; pointer-events:none; padding:0 12px; }
  .tb-toast { background:#fff; border:3px solid #000; box-shadow:4px 4px 0 #000; padding:.85rem 1.15rem; font-weight:800; font-size:.88rem; max-width:min(400px,92vw); opacity:0; transform:translateY(12px); transition:opacity .22s,transform .28s cubic-bezier(.34,1.56,.64,1); }
  .tb-toast.show { opacity:1; transform:translateY(0); }
  .hidden { display:none !important; }
</style>
</head>
<body>
<div class="grid-bg"></div>
<div class="card">
  <div class="brand-wrap">
    <div class="brand"><span class="brand-box">Trex</span><span class="brand-bridge">Bridge</span></div>
    <p class="subtitle" id="pageSub">Username &amp; password</p>
  </div>
  <div class="error-box" id="errBox"></div>
  <div class="ok-box" id="okBox"></div>

  <div id="viewLogin">
    <form id="loginForm" autocomplete="on">
      <div class="form-group">
        <label class="field-label-box fl-user" for="username">Username</label>
        <input class="neo-input" type="text" id="username" name="username" placeholder="Username" value="" required autocomplete="username" autofocus />
      </div>
      <div class="form-group">
        <label class="field-label-box fl-pass" for="password">Password</label>
        <div class="input-wrap">
          <input class="neo-input" type="password" id="password" name="password" placeholder="••••••••" required autocomplete="current-password" />
          <button type="button" class="toggle-pass" data-for="password" title="Show/hide" aria-label="Toggle password">
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
        </div>
      </div>
      <button type="submit" class="btn-main" id="loginBtn"><span>Sign in</span></button>
    </form>
    <button type="button" class="btn-forgot" id="btnForgot">Forgot password?</button>
    <div class="social-row">
      <a class="btn-sec btn-tg" href="https://t.me/TrexBridgePanel" target="_blank" rel="noopener">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
        Support
      </a>
      <a class="btn-sec btn-gh" href="https://github.com/icubaby/TrexBridge" target="_blank" rel="noopener">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/></svg>
        GitHub
      </a>
    </div>
  </div>

  <div id="viewForgotToken" class="hidden">
    <button type="button" class="btn-back" id="backFromToken"><span style="font-size:16px;line-height:1">←</span> Back</button>
    <p class="step-hint">Step 1/2 — Cloudflare API token</p>
    <div class="form-group">
      <label class="field-label-box fl-token" for="cfToken">Cloudflare API Token</label>
      <input class="neo-input" type="password" id="cfToken" placeholder="CF API token" autocomplete="off" />
    </div>
    <button type="button" class="btn-main btn-sky" style="background:#38bdf8;color:#000" id="btnTokenNext">Continue</button>
  </div>

  <div id="viewForgotReset" class="hidden">
    <button type="button" class="btn-back" id="backFromReset"><span style="font-size:16px;line-height:1">←</span> Back</button>
    <p class="step-hint">Step 2/2 — New password</p>
    <div class="form-group">
      <label class="field-label-box fl-newuser" for="newUser">New username</label>
      <input class="neo-input" type="text" id="newUser" placeholder="Username" value="" autocomplete="username" />
    </div>
    <div class="form-group">
      <label class="field-label-box fl-newpass" for="newPass">New password</label>
      <div class="input-wrap">
        <input class="neo-input" type="password" id="newPass" placeholder="min 4 characters" autocomplete="new-password" />
        <button type="button" class="toggle-pass" data-for="newPass" title="Show/hide" aria-label="Toggle password">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>
      </div>
    </div>
    <div class="form-group">
      <label class="field-label-box fl-confirm" for="newPass2">Confirm password</label>
      <div class="input-wrap">
        <input class="neo-input" type="password" id="newPass2" placeholder="Confirm password" autocomplete="new-password" />
        <button type="button" class="toggle-pass" data-for="newPass2" title="Show/hide" aria-label="Toggle password">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>
      </div>
    </div>
    <button type="button" class="btn-main btn-yellow" style="background:#facc15;color:#000" id="btnReset">Reset password</button>
  </div>

  <p class="footer">TrexBridge · Login</p>
</div>
<div id="toast-wrap"></div>
<script>
(function () {
  var savedToken = "";
  function $(id) { return document.getElementById(id); }
  function showErr(msg) {
    var e = $("errBox"), o = $("okBox");
    o.classList.remove("show"); o.textContent = "";
    if (!msg) { e.classList.remove("show"); e.textContent = ""; return; }
    e.textContent = msg; e.classList.add("show");
  }
  function showOk(msg) {
    var e = $("errBox"), o = $("okBox");
    e.classList.remove("show"); e.textContent = "";
    if (!msg) { o.classList.remove("show"); o.textContent = ""; return; }
    o.textContent = msg; o.classList.add("show");
  }
  function showToast(text, type) {
    var kind = "info";
    if (type === true || type === "error" || type === "err") kind = "error";
    else if (type === "success" || type === "ok" || type === false) kind = type === false ? "info" : "success";
    else if (typeof type === "string") kind = type;
    var icons = {
      error: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>',
      success: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="M22 4L12 14.01l-3-3"/></svg>',
      info: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.4"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>'
    };
    var colors = { error: "#fda4af", success: "#4ade80", info: "#fde68a" };
    var bars = { error: "#e11d48", success: "#16a34a", info: "#eab308" };
    var wrap = $("toast-wrap");
    if (!wrap) return;
    while (wrap.children.length >= 5) { try { wrap.removeChild(wrap.firstChild); } catch (e) { break; } }
    var t = document.createElement("div");
    t.setAttribute("role", "status");
    t.style.cssText = "position:relative;overflow:hidden;background:#fff;border:3px solid #000;box-shadow:4px 4px 0 #000;padding:0.85rem 1.15rem 0.75rem 1rem;font-weight:800;font-size:0.88rem;display:flex;align-items:center;gap:10px;width:max-content;max-width:min(400px,92vw);opacity:0;transform:translateY(14px);transition:opacity .22s ease,transform .28s cubic-bezier(.34,1.56,.64,1);";
    var bar = document.createElement("div");
    bar.style.cssText = "position:absolute;top:0;left:0;right:0;height:5px;border-bottom:2px solid #000;background:" + (bars[kind] || bars.info) + ";";
    var icon = document.createElement("span");
    icon.style.cssText = "width:32px;height:32px;border:2.5px solid #000;background:" + (colors[kind] || colors.info) + ";display:inline-flex;align-items:center;justify-content:center;box-shadow:2px 2px 0 #000;flex-shrink:0;";
    icon.innerHTML = icons[kind] || icons.info;
    var msg = document.createElement("span");
    msg.style.cssText = "flex:1;text-align:left;line-height:1.35;";
    msg.textContent = String(text || "");
    t.appendChild(bar); t.appendChild(icon); t.appendChild(msg);
    wrap.appendChild(t);
    requestAnimationFrame(function () { t.style.opacity = "1"; t.style.transform = "translateY(0)"; });
    setTimeout(function () {
      t.style.opacity = "0"; t.style.transform = "translateY(10px)";
      setTimeout(function () { try { t.remove(); } catch (e) {} }, 260);
    }, 2800);
  }
  function setView(name) {
    $("viewLogin").classList.toggle("hidden", name !== "login");
    $("viewForgotToken").classList.toggle("hidden", name !== "token");
    $("viewForgotReset").classList.toggle("hidden", name !== "reset");
    if (name === "login") $("pageSub").textContent = "Username & password";
    if (name === "token") $("pageSub").textContent = "Forgot password · Token";
    if (name === "reset") $("pageSub").textContent = "Forgot password · New credentials";
    showErr("");
    showOk("");
  }
  document.querySelectorAll(".toggle-pass").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var id = btn.getAttribute("data-for");
      var i = $(id);
      if (i) i.type = i.type === "password" ? "text" : "password";
    });
  });
  $("btnForgot").onclick = function () { setView("token"); };
  $("backFromToken").onclick = function () { savedToken = ""; setView("login"); };
  $("backFromReset").onclick = function () { setView("token"); };
  $("btnTokenNext").onclick = function () {
    var token = ($("cfToken").value || "").trim();
    if (!token) {
      showErr("Cloudflare API token is required");
      showToast("Token required", true);
      return;
    }
    savedToken = token;
    setView("reset");
    showOk("Token accepted — choose new credentials");
  };
  $("btnReset").onclick = async function () {
    var token = savedToken || ($("cfToken").value || "").trim();
    var newUser = ($("newUser").value || "admin").trim() || "admin";
    var newPass = ($("newPass").value || "").trim();
    var newPass2 = ($("newPass2").value || "").trim();
    if (!token) { showErr("Token missing — go back to step 1"); return; }
    if (!newPass || newPass.length < 4) { showErr("Password must be at least 4 characters"); return; }
    if (newPass !== newPass2) { showErr("Passwords do not match"); return; }
    var btn = $("btnReset");
    btn.disabled = true;
    showErr("");
    try {
      var res = await fetch("/api/recover", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ api_token: token, new_password: newPass, username: newUser })
      });
      var j = await res.json().catch(function () { return {}; });
      if (res.ok && j.success) {
        showToast("Password reset — login with " + newUser);
        $("username").value = newUser;
        $("password").value = newPass;
        savedToken = "";
        $("cfToken").value = "";
        $("newPass").value = "";
        $("newPass2").value = "";
        setView("login");
        showOk("Password updated. Sign in with your new credentials.");
      } else {
        showErr(j.error || "Reset failed");
        showToast(j.error || "Reset failed", true);
      }
    } catch (e) {
      showErr("Connection error");
      showToast("Connection error", true);
    } finally {
      btn.disabled = false;
    }
  };
  $("loginForm").addEventListener("submit", async function (e) {
    e.preventDefault();
    var btn = $("loginBtn");
    var username = ($("username").value || "admin").trim() || "admin";
    var password = ($("password").value || "").trim();
    showErr("");
    showOk("");
    if (!password) {
      showErr("");
      showToast("Password is required", true);
      return;
    }
    btn.disabled = true;
    try {
      var res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ username: username, password: password })
      });
      var j = await res.json().catch(function () { return {}; });
      if (res.ok && j.success) {
        showToast("Welcome, " + username, "success");
        location.replace("/app");
      } else {
        showErr("");
        showToast(j.error || "Wrong username or password", true);
        btn.disabled = false;
      }
    } catch (err2) {
      showErr("");
      showToast("Connection error", true);
      btn.disabled = false;
    }
  });
})();
</script>
</body>
</html>`,
	setup: `<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>TrexBridge — Setup</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700;800;900&family=Public+Sans:wght@600;700;800&display=swap" rel="stylesheet">
<style>
  :root { --bg:#f5f0e8; --card:#fffdf5; --ink:#0a0a0a; --muted:#71717a; --green:#22c55e; --yellow:#facc15; --sky:#fcd34d; --violet:#c4b5fd; }
  * { box-sizing:border-box; margin:0; padding:0; border-radius:0 !important; }
  body { font-family:"Public Sans",system-ui,sans-serif; font-weight:700; background:var(--bg); color:var(--ink); min-height:100vh; display:flex; align-items:center; justify-content:center; padding:16px 12px; }
  .grid-bg { position:fixed; inset:-20px; z-index:0; pointer-events:none; background-color:#f5f0e8;
      background-image:linear-gradient(to right,rgba(0,0,0,.11) 1.5px,transparent 1.5px),linear-gradient(to bottom,rgba(0,0,0,.11) 1.5px,transparent 1.5px);
      background-size:40px 40px; background-position:-12px -12px; }
  .card { position:relative; z-index:1; width:100%; max-width:400px; background:var(--card); border:3.5px solid #000; box-shadow:6px 6px 0 #000; padding:1.75rem 1.4rem 1.5rem; }
  .brand-wrap { text-align:center; margin-bottom:1.25rem; }
  .brand { display:inline-flex; align-items:center; font-family:Archivo,sans-serif; font-size:1.65rem; font-weight:900; }
  .brand-box { position:relative; overflow:hidden; background:var(--green); padding:4px 12px; border:2.5px solid #000; box-shadow:3px 3px 0 #000; }
  .brand-box::after { content:""; position:absolute; top:0; bottom:0; left:-60%; width:40%; background:linear-gradient(90deg,transparent,rgba(255,255,255,.45),transparent); transform:skewX(-18deg); animation:shine 3.8s ease-in-out infinite; }
  @keyframes shine { 0%{left:-60%} 100%{left:130%} }
  .brand-bridge { padding-left:9px; }
  .subtitle { margin-top:10px; font-size:.82rem; font-weight:800; color:var(--muted); }
  .field-label { display:block; font-size:11px; font-weight:800; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin-bottom:8px; }
  .field-label-box { display:inline-block; font-size:11px; font-weight:800; text-transform:uppercase; letter-spacing:.06em; color:#000; margin-bottom:8px; padding:4px 10px; border:2.5px solid #000; box-shadow:2px 2px 0 #000; }
  .fl-user { background:#7dd3fc; }
  .fl-pass { background:#facc15; }
  .form-group { margin-bottom:1rem; }
  .neo-input { width:100%; background:#fffef8 !important; border:2.5px solid #000 !important; box-shadow:3px 3px 0 #000 !important; padding:12px 14px; font-family:inherit; font-weight:700; font-size:15px; outline:none; }
  .neo-input:focus { box-shadow:5px 5px 0 #000 !important; }
  .input-wrap { position:relative; }
  .input-wrap .neo-input { padding-right:48px; }
  .toggle-pass { position:absolute; right:7px; top:50%; transform:translateY(-50%); width:34px; height:34px; border:2.5px solid #000; background:#fff; box-shadow:2px 2px 0 #000; cursor:pointer; display:flex; align-items:center; justify-content:center; }
  .error-box { display:none; padding:.7rem .95rem; border:3px solid #000; background:#fecaca; box-shadow:3px 3px 0 #000; font-size:.8rem; font-weight:800; margin-bottom:1rem; }
  .error-box.show { display:block; }
  .btn-main { width:100%; min-height:52px; border:3px solid #000; background:var(--yellow); box-shadow:4px 4px 0 #000; font-family:inherit; font-weight:900; font-size:.95rem; cursor:pointer; display:flex; align-items:center; justify-content:center; gap:8px; }
  .btn-main:disabled { opacity:.6; }
  .row-btns { display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-top:10px; }
  .btn-sec { min-height:44px; border:2.5px solid #000; box-shadow:3px 3px 0 #000; font-family:inherit; font-weight:800; font-size:.8rem; cursor:pointer; display:flex; align-items:center; justify-content:center; gap:6px; text-decoration:none; color:#000; }
  .btn-tg { background:#7dd3fc; }
  .btn-gh { background:#a78bfa; color:#000 !important; }
  .footer { margin-top:1.25rem; text-align:center; font-size:.68rem; font-weight:700; color:var(--muted); }
</style>
</head>
<body>
<div class="grid-bg"></div>
<div class="card">
  <div class="brand-wrap">
    <div class="brand"><span class="brand-box">Trex</span><span class="brand-bridge">Bridge</span></div>
    <p class="subtitle">Initial setup — choose username &amp; password</p>
  </div>
  <div class="error-box" id="errBox"></div>
  <form id="setupForm" autocomplete="on">
    <div class="form-group">
      <label class="field-label-box fl-user" for="username">Username</label>
      <input class="neo-input" type="text" id="username" name="username" placeholder="Username" value="" required />
    </div>
    <div class="form-group">
      <label class="field-label-box fl-pass" for="password">Password</label>
      <div class="input-wrap">
        <input class="neo-input" type="password" id="password" name="password" placeholder="At least 4 characters" required minlength="4" />
        <button type="button" class="toggle-pass" id="togglePass" aria-label="Toggle">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
        </button>
      </div>
    </div>
    <button type="submit" class="btn-main" id="saveBtn">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.4"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      <span>Save &amp; continue</span>
    </button>
  </form>
  <div class="row-btns">
    <a class="btn-sec btn-tg" href="https://t.me/TrexBridgePanel" target="_blank" rel="noopener">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
      Support
    </a>
    <a class="btn-sec btn-gh" href="https://github.com/icubaby/TrexBridge" target="_blank" rel="noopener">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/></svg>
      GitHub
    </a>
  </div>
  <p class="footer">TrexBridge · First-time setup</p>
</div>
<script>
document.getElementById("togglePass").onclick = function () {
  var i = document.getElementById("password");
  i.type = i.type === "password" ? "text" : "password";
};
document.getElementById("setupForm").addEventListener("submit", async function (e) {
  e.preventDefault();
  var err = document.getElementById("errBox");
  var btn = document.getElementById("saveBtn");
  var username = (document.getElementById("username").value || "admin").trim() || "admin";
  var password = (document.getElementById("password").value || "").trim();
  err.classList.remove("show");
  if (password.length < 4) {
    err.textContent = "Password must be at least 4 characters";
    err.classList.add("show");
    return;
  }
  btn.disabled = true;
  try {
    var res = await fetch("/api/setup-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ password: password, username: username })
    });
    var j = await res.json().catch(function () { return {}; });
    if (res.ok && (j.success || !j.error)) {
      var loginRes = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ username: username, password: password })
      });
      location.replace(loginRes.ok ? "/app" : "/login");
    } else {
      err.textContent = j.error || "Setup failed";
      err.classList.add("show");
      btn.disabled = false;
    }
  } catch (ex) {
    err.textContent = "Connection error";
    err.classList.add("show");
    btn.disabled = false;
  }
});
</script>
</body>
</html>`,
	panel: `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>TrexBridge</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700;800;900&family=Public+Sans:wght@600;700;800&display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0" rel="stylesheet"/>
<style>

    :root {
      --bg: #f5f0e8;
      --card: #fffdf5;
      --ink: #0a0a0a;
      --muted: #71717a;
      --green: #22c55e;
      --lime: #fde68a;
      --yellow: #facc15;
      --sky: #f9a8d4;
      --pink: #f472b6;
      --violet: #c4b5fd;
      --red: #ef4444;
    }
    body {
      margin: 0;
      font-family: "Public Sans", system-ui, sans-serif;
      font-weight: 700;
      background: var(--bg);
      color: var(--ink);
      overflow-x: hidden;
    }
    * { border-radius: 0 !important; box-sizing: border-box; }
    ::-webkit-scrollbar { width: 10px; }
    ::-webkit-scrollbar-track { background: #e8e0d4; border-left: 2px solid #000; }
    ::-webkit-scrollbar-thumb { background: var(--green); border: 2px solid #000; }
    .grid-bg {
      position: fixed; inset: -20px; z-index: 0; pointer-events: none;
      background-color: #f5f0e8;
      background-image:
        linear-gradient(to right, rgba(0,0,0,0.11) 1.5px, transparent 1.5px),
        linear-gradient(to bottom, rgba(0,0,0,0.11) 1.5px, transparent 1.5px);
      background-size: 40px 40px;
      background-position: -12px -12px;
      animation: gridDrift 23s ease-in-out infinite alternate;
    }
    @keyframes gridDrift {
      0% { background-position: -12px -12px; }
      100% { background-position: 8px 8px; }
    }
    .stars-layer {
      position: fixed; inset: 0; z-index: 0; pointer-events: none; overflow: hidden;
    }
    .star-float {
      position: absolute;
      opacity: 0.55;
      animation: starFloat linear infinite;
      filter: drop-shadow(0 0 0 transparent);
    }
    .star-float.g { color: #facc15; fill: #facc15; }
    .star-float.k { color: #0a0a0a; fill: #0a0a0a; opacity: 0.18; }
    .star-float.y { color: #facc15; fill: #facc15; opacity: 0.35; }
    @keyframes starFloat {
      0% { transform: translate(0, 0) rotate(0deg) scale(1); }
      33% { transform: translate(12px, -18px) rotate(8deg) scale(1.05); }
      66% { transform: translate(-10px, 10px) rotate(-6deg) scale(0.96); }
      100% { transform: translate(0, 0) rotate(0deg) scale(1); }
    }
    @keyframes softPulse {
      0%, 100% { opacity: 0.4; }
      50% { opacity: 0.7; }
    }
    .content-wrap { position: relative; z-index: 1; }
    .glass-header {
      background: rgba(245, 240, 232, 0.88);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
    }
    @keyframes fadeUp {
      from { opacity: 0; transform: translateY(14px); }
      to { opacity: 1; transform: translateY(0); }
    }
    @keyframes popIn {
      0% { opacity: 0; transform: scale(0.96); }
      100% { opacity: 1; transform: scale(1); }
    }
    @keyframes shine {
      0% { left: -60%; } 100% { left: 130%; }
    }
    .anim-in { animation: fadeUp 0.4s ease both; }
    .anim-pop { animation: popIn 0.35s ease both; }
    .lift {
      transition: transform 0.12s ease, box-shadow 0.12s ease;
    }
    .lift:hover {
      transform: translate(-2px, -2px);
      box-shadow: 7px 7px 0 #000 !important;
    }
    .lift:active {
      transform: translate(1px, 1px);
      box-shadow: 2px 2px 0 #000 !important;
    }
    .brand-box { position: relative; overflow: hidden; }
    .brand-box::after {
      content: "";
      position: absolute; top: 0; bottom: 0; left: -60%; width: 40%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.45), transparent);
      transform: skewX(-18deg);
      animation: shine 3.8s ease-in-out infinite;
    }
    .material-symbols-outlined {
      font-family: 'Material Symbols Outlined';
      font-weight: normal; font-style: normal; font-size: 24px;
      line-height: 1; display: inline-block;
      -webkit-font-smoothing: antialiased;
      font-variation-settings: 'FILL' 0, 'wght' 400, 'GRAD' 0, 'opsz' 24;
    }
    .glass-nav {
      background: rgba(245, 240, 232, 0.88);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
    }
    .bottom-nav {
      display: flex;
      width: 100%;
      gap: 8px;
    }
    .nav-item {
      flex: 1;
      position: relative;
      overflow: hidden;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 48px;
      padding: 10px 8px;
      font-weight: 900;
      font-size: 0.95rem;
      letter-spacing: -0.02em;
      color: #3f3f46;
      background: transparent;
      border: 2.5px solid transparent;
      cursor: pointer;
      transition: color 0.15s ease, background 0.15s ease, box-shadow 0.15s ease;
    }
    .nav-item .nav-label {
      position: relative;
      z-index: 1;
      font-family: Archivo, sans-serif;
      font-weight: 900;
      font-size: 1.05rem;
    }
    .nav-item.active {
      color: #000;
      background: #facc15;
      border-color: #000;
      box-shadow: 3px 3px 0 #000;
    }
    .nav-item.active::after {
      content: "";
      position: absolute;
      top: 0; left: -60%;
      width: 45%; height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.28), transparent);
      animation: navShine 2.4s ease-in-out infinite;
      pointer-events: none;
    }
    @keyframes navShine {
      0% { left: -60%; }
      100% { left: 130%; }
    }
    .nav-item:active { transform: translate(1px, 1px); }
    .neo-input {
      background: linear-gradient(to left, #fff 0%, #fef3c7 100%) !important;
      border: 2.5px solid #000 !important;
      box-shadow: 3px 3px 0 #000 !important;
    }
    .neo-input:focus {
      background: linear-gradient(to left, #fff 0%, #fde68a 100%) !important;
      box-shadow: 5px 5px 0 #000 !important;
      transform: translate(-1px, -1px);
    }
    .input-wrap {
      position: relative;
      display: flex;
      align-items: center;
    }
    .input-wrap .neo-input {
      padding-left: 44px;
    }
    .input-wrap .in-ico {
      position: absolute;
      left: 12px;
      z-index: 1;
      font-size: 20px !important;
      color: #000;
      pointer-events: none;
    }
    .onoff {
      min-width: 52px;
      text-align: center;
      font-size: 11px;
      font-weight: 900;
      padding: 6px 10px;
      border: 2.5px solid #000;
      flex-shrink: 0;
    }
    .onoff.on { background: #facc15; }
    .onoff.off { background: #e4e4e7; }
    .field-label {
      display: inline-block;
      font-size: 11px;
      font-weight: 900;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #000;
      margin-bottom: 8px;
      padding: 4px 10px;
      border: 2.5px solid #000;
      box-shadow: 2px 2px 0 #000;
      background: #facc15;
    }
    .neo-input {
      width: 100%;
      background: #fff;
      border: 2.5px solid #000;
      box-shadow: 3px 3px 0 #000;
      padding: 12px 14px;
      font-family: inherit;
      font-weight: 700;
      font-size: 15px;
      outline: none;
      transition: box-shadow 0.12s, transform 0.12s;
    }
    .neo-input:focus {
      box-shadow: 5px 5px 0 #000;
      transform: translate(-1px, -1px);
    }
    .neo-input::placeholder { color: #a1a1aa; font-weight: 600; }
    /* hide number spinners */
    .neo-input[type=number]::-webkit-outer-spin-button,
    .neo-input[type=number]::-webkit-inner-spin-button {
      -webkit-appearance: none; margin: 0;
    }
    .neo-input[type=number] { -moz-appearance: textfield; appearance: textfield; }
    .seg {
      display: grid;
      border: 2.5px solid #000;
      box-shadow: 3px 3px 0 #000;
      overflow: hidden;
      background: #fff;
    }
    .seg button {
      min-height: 42px;
      border: none;
      border-right: 2.5px solid #000;
      background: #fff;
      font-family: inherit;
      font-weight: 800;
      font-size: 13px;
      cursor: pointer;
      transition: background 0.12s;
    }
    .seg button:last-child { border-right: none; }
    .seg button.on { background: #facc15; }
    
    .empty-hero {
      padding: 8px 6px 12px;
      background: transparent;
      border: none;
      box-shadow: none;
    }
    .empty-marquee {
      border: 3px solid #000;
      background: #f5f0e8;
      overflow: hidden;
      white-space: nowrap;
      padding: 14px 0;
      box-shadow: 4px 4px 0 #000;
      position: relative;
    }
    .empty-marquee-track {
      display: flex;
      width: max-content;
      animation: emptyMarquee 22s linear infinite;
      will-change: transform;
    }
    .empty-marquee-group {
      display: flex;
      align-items: center;
      gap: 18px;
      padding-right: 18px;
      flex-shrink: 0;
      box-sizing: border-box;
    }
    .empty-marquee-text {
      font-family: "Archivo", sans-serif;
      font-weight: 900;
      font-size: 15px;
      letter-spacing: 0.04em;
      color: #0a0a0a;
      text-transform: uppercase;
    }
    .empty-ico {
      width: 36px;
      height: 36px;
      border: 2.5px solid #000;
      box-shadow: 2px 2px 0 #000;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      flex-shrink: 0;
    }
    .empty-ico-quick { background: #fb923c; }
    .empty-ico-new { background: #a78bfa; }
    @keyframes emptyMarquee {
      0% { transform: translate3d(0, 0, 0); }
      100% { transform: translate3d(-33.333%, 0, 0); }
    }
    .chip-pick {



      flex: 1;
      min-width: 3.5rem;
      height: 44px;
      padding: 0 14px;
      border: 2.5px solid #000;
      box-shadow: 3px 3px 0 #000;
      background: #fffef8;
      font-family: Archivo, sans-serif;
      font-weight: 900;
      font-size: 14px;
      letter-spacing: 0.02em;
      cursor: pointer;
      transition: transform .1s ease, box-shadow .1s ease, background .12s ease;
    }
    .chip-pick-on {
      position: relative;
      overflow: hidden;
      background: #facc15 !important;
      color: #000 !important;
      box-shadow: 4px 4px 0 #000;
    }
    .chip-pick-on::after {
      content: "";
      position: absolute;
      top: 0; left: -60%;
      width: 45%; height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.28), transparent);
      animation: navShine 2.4s ease-in-out infinite;
      pointer-events: none;
    }
    .chip-on-shine::after {
      content: "";
      position: absolute;
      top: 0; left: -60%;
      width: 45%; height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.28), transparent);
      animation: navShine 2.4s ease-in-out infinite;
      pointer-events: none;
    }
    .chip-on-shine .material-symbols-outlined { color: #000 !important; }
    .text-white .material-symbols-outlined { color: #fff !important; }
    button.text-white .material-symbols-outlined { color: #fff !important; }
    .nb-card-h .t { color: #000 !important; }
    .nb-card-h .d { color: rgba(0,0,0,0.55) !important; }
    .nb-card-h .material-symbols-outlined { color: #000 !important; }
    .kpi-card {
      position: relative;
      overflow: hidden;
      background: #fff7ed;
    }
    .user-card {
      background: #fff7ed;
      border: 3px solid #000;
      box-shadow: 5px 5px 0 #000;
    }
    .chip-pick:hover { filter: brightness(1.03); }
    .chip-pick:active { transform: translate(2px,2px); box-shadow: 1px 1px 0 #000; }
    .seg button.on { background: #facc15 !important; }


    .seg button:hover:not(.on) { background: #f5f0e8; }
    .nb-tabs {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 8px;
      margin-bottom: 18px;
    }
    .nb-tabs button {
      min-height: 44px;
      border: 2.5px solid #000;
      background: #fff;
      box-shadow: 3px 3px 0 #000;
      font-family: inherit;
      font-weight: 800;
      font-size: 13px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      color: #000;
      transition: background 0.12s, transform 0.1s, box-shadow 0.1s;
    }
    .nb-tabs button .material-symbols-outlined { font-size: 18px; }
    
    .nb-tabs button.tab-basic { background: #2563eb !important; color: #fff !important; }
    .nb-tabs button.tab-basic .material-symbols-outlined { color: #fff !important; }
    .nb-tabs button.tab-security { background: #dc2626 !important; color: #fff !important; }
    .nb-tabs button.tab-security .material-symbols-outlined { color: #fff !important; }
    .nb-tabs button.tab-network { background: #7c3aed !important; color: #fff !important; }
    .nb-tabs button.tab-network .material-symbols-outlined { color: #fff !important; }
    .nb-tabs button.tab-account { background: #7c3aed !important; color: #fff !important; }
    .nb-tabs button.tab-account .material-symbols-outlined { color: #fff !important; }
    .nb-tabs button.tab-update { background: #db2777 !important; color: #fff !important; }
    .nb-tabs button.tab-update .material-symbols-outlined { color: #fff !important; }
    .nb-tabs button.tab-system { background: #16a34a !important; color: #fff !important; }
    .nb-tabs button.tab-system .material-symbols-outlined { color: #fff !important; }
    .nb-tabs button.tab-basic.on,
    .nb-tabs button.tab-security.on,
    .nb-tabs button.tab-network.on,
    .nb-tabs button.tab-account.on,
    .nb-tabs button.tab-update.on,
    .nb-tabs button.tab-system.on {
      background: #facc15 !important;
      color: #000 !important;
    }
    .nb-tabs button.on {
      position: relative;
      overflow: hidden;
      color: #000 !important;
      box-shadow: 4px 4px 0 #000;
      transform: translate(-1px, -1px);
    }
    .nb-tabs button.on .material-symbols-outlined { color: #000 !important; }
    .nb-tabs button.on::after {
      content: "";
      position: absolute;
      top: 0; left: -60%;
      width: 45%; height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.28), transparent);
      animation: navShine 2.4s ease-in-out infinite;
      pointer-events: none;
    }
    .nb-tabs button:hover:not(.on) {
      filter: brightness(1.08);
      color: #fff;
    }
    .nb-tabs button:hover:not(.on) .material-symbols-outlined { color: #fff; }
    .divider-star {
      display: flex; align-items: center; gap: 12px;
      margin: 20px 0;
    }
    .divider-star .line {
      flex: 1; height: 3px; background: #000;
      opacity: 1;
    }
    .divider-star {
      display: flex; align-items: center; gap: 12px;
      margin: 18px 0;
    }
    .divider-star .line { flex: 1; height: 2.5px; background: #000; }
    .neo-input {
      background: #fffef8 !important;
    }
    .neo-input:focus {
      background: #fff !important;
    }
    .nb-card {
      background: #fffdf5;
      border: 3px solid #000;
      box-shadow: 5px 5px 0 #000;
      overflow: hidden;
      margin-bottom: 14px;
    }
    .nb-card-h {
      padding: 14px 16px;
      border-bottom: 3px solid #000;
      background: #fff;
    }
    .nb-card-h .t { font-family: Archivo, sans-serif; font-weight: 900; font-size: 15px; }
    .nb-card-h .d { font-size: 11px; font-weight: 700; color: #71717a; margin-top: 2px; }
    .nb-card-b { padding: 16px; }
    .nb-card-f {
      padding: 12px 16px;
      border-top: 3px solid #000;
      background: #fff;
    }
    .seg {
      display: grid;
      gap: 0;
      border: 3px solid #000;
      box-shadow: 4px 4px 0 #000;
      overflow: hidden;
      background: #fff;
    }
    .seg button {
      min-height: 48px;
      border: none;
      border-right: 3px solid #000;
      background: #fff;
      font-family: inherit;
      font-weight: 800;
      font-size: 13px;
      cursor: pointer;
      transition: background 0.12s, color 0.12s;
    }
    .seg button:last-child { border-right: none; }
    .seg button.on {
      background: #facc15;
      color: #000;
    }
    .seg button:hover:not(.on) { background: #f5f0e8; }
    .field-box {
      border: 3px solid #000;
      background: #fff;
      box-shadow: 4px 4px 0 #000;
      padding: 14px;
    }
    .field-box .field-label { margin-bottom: 10px; }
    .field-label.fl-c-yellow { background: #facc15; color: #000; }
    .field-label.fl-c-blue { background: #7dd3fc; color: #000; }
    .field-label.fl-c-purple { background: #a78bfa; color: #000; }
    .field-label.fl-c-red { background: #ef4444; color: #fff; }
    .field-label.fl-c-green { background: #22c55e; color: #000; }
    .field-label.fl-c-orange { background: #fb923c; color: #000; }
    .field-label.fl-c-pink { background: #f9a8d4; color: #000; }

    .pill {
      display: inline-flex; align-items: center; justify-content: center;
      padding: 8px 14px;
      border: 2.5px solid #000;
      background: #fff;
      box-shadow: 2px 2px 0 #000;
      font-weight: 800; font-size: 13px;
      cursor: pointer; user-select: none;
      transition: background 0.1s, transform 0.1s, box-shadow 0.1s;
    }
    .pill:hover {
      transform: translate(-1px, -1px);
      box-shadow: 3px 3px 0 #000;
    }
    .pill.on { background: var(--lime); }
    .pill.on-y { background: var(--yellow); }
    .pill.on-s { background: #fcd34d; }
    .pill.on-p { background: #f9a8d4; }
    .op-chip {
      display: flex; flex-direction: column; align-items: flex-start;
      gap: 2px; padding: 10px 12px;
      border: 2.5px solid #000;
      background: #fff;
      box-shadow: 2px 2px 0 #000;
      cursor: pointer; min-width: 0;
      transition: background 0.1s, transform 0.1s;
    }
    .op-chip:hover { transform: translate(-1px, -1px); box-shadow: 3px 3px 0 #000; }
    .op-chip.on { background: var(--lime); }
    .op-chip .op-name { font-weight: 800; font-size: 12px; }
    .op-chip .op-count { font-weight: 700; font-size: 10px; color: var(--muted); }
    .sec {
      background: var(--card);
      border: 3px solid #000;
      box-shadow: 5px 5px 0 #000;
      margin-bottom: 16px;
      overflow: hidden;
    }
    .sec-h {
      display: flex; align-items: center; gap: 12px;
      padding: 14px 16px;
      border-bottom: 3px solid #000;
      background: #fff;
    }
    .sec-icon {
      width: 40px; height: 40px;
      border: 2.5px solid #000;
      display: flex; align-items: center; justify-content: center;
      flex-shrink: 0;
    }
    .sec-b { padding: 16px; }
    .toggle-row {
      display: flex; align-items: center; justify-content: space-between;
      gap: 12px; padding: 12px 14px;
      border: 2.5px solid #000; background: #fff;
      box-shadow: 2px 2px 0 #000;
      cursor: pointer;
    }
    .toggle-sw {
      width: 48px; height: 26px;
      border: 2.5px solid #000;
      background: #e4e4e7;
      position: relative; flex-shrink: 0;
    }
    .toggle-sw.on { background: var(--green); }
    .toggle-sw::after {
      content: "";
      position: absolute; top: 2px; left: 2px;
      width: 18px; height: 18px; background: #000;
      transition: left 0.15s;
    }
    .toggle-sw.on::after { left: 24px; }
    .toast {
      position: fixed; bottom: 96px; left: 50%; transform: translateX(-50%);
      background: #fff; border: 3px solid #000; box-shadow: 4px 4px 0 #000;
      padding: 12px 20px; font-weight: 800; font-size: 14px;
      z-index: 200; animation: fadeUp 0.25s ease both; max-width: 90vw;
    }
    .kpi-ico { font-size: 18px !important; }
    @media (min-width: 768px) {
      .kpi-ico { font-size: 21px !important; }
    }
    .basic-chip {
      min-height: 42px;
      display: flex; align-items: center; justify-content: center;
      border: 2.5px solid #000;
      font-weight: 800; font-size: 13px;
      box-shadow: 2px 2px 0 #000;
      transition: transform 0.1s, box-shadow 0.1s, background 0.1s;
      cursor: pointer; user-select: none;
    }
    .basic-chip:hover { transform: translate(-1px,-1px); box-shadow: 3px 3px 0 #000; }
    .basic-chip.on { box-shadow: 3px 3px 0 #000; transform: translate(-1px,-1px); }
    .input-fill {
      width: 100%;
      background: #fff;
      border: 2.5px solid #000;
      box-shadow: 3px 3px 0 #000;
      padding: 13px 14px;
      font-family: inherit;
      font-weight: 700;
      font-size: 15px;
      outline: none;
    }
    .input-fill:focus { box-shadow: 5px 5px 0 #000; }
    .input-fill::placeholder { color: #a1a1aa; font-weight: 600; }
    .sticky-create {
      position: sticky; bottom: 88px; z-index: 40;
      padding: 0 0 8px;
      background: linear-gradient(to top, var(--bg) 60%, transparent);
    }
  

#toast-wrap{position:fixed;left:0;right:0;bottom:100px;z-index:9999;display:flex;flex-direction:column;align-items:center;gap:8px;pointer-events:none;padding:0 12px}
.tb-toast{background:#fff;border:3px solid #000;box-shadow:4px 4px 0 #000;padding:12px 16px;font-weight:800;font-size:13px;max-width:min(400px,92vw);opacity:0;transform:translateY(12px);transition:opacity .2s,transform .25s}
.tb-toast.show{opacity:1;transform:translateY(0)}
.tb-toast.err{background:#fecaca}

</style>
</head>
<body>
<div class="grid-bg"></div>
<div id="root"><div style="padding:24px;font-family:Public Sans,sans-serif;font-weight:800;text-align:center;">Loading…</div></div>
<div id="toast-wrap"></div>
<script>
/**
 * @license React
 * react.production.min.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
(function(){'use strict';(function(c,x){"object"===typeof exports&&"undefined"!==typeof module?x(exports):"function"===typeof define&&define.amd?define(["exports"],x):(c=c||self,x(c.React={}))})(this,function(c){function x(a){if(null===a||"object"!==typeof a)return null;a=V&&a[V]||a["@@iterator"];return"function"===typeof a?a:null}function w(a,b,e){this.props=a;this.context=b;this.refs=W;this.updater=e||X}function Y(){}function K(a,b,e){this.props=a;this.context=b;this.refs=W;this.updater=e||X}function Z(a,b,
e){var m,d={},c=null,h=null;if(null!=b)for(m in void 0!==b.ref&&(h=b.ref),void 0!==b.key&&(c=""+b.key),b)aa.call(b,m)&&!ba.hasOwnProperty(m)&&(d[m]=b[m]);var l=arguments.length-2;if(1===l)d.children=e;else if(1<l){for(var f=Array(l),k=0;k<l;k++)f[k]=arguments[k+2];d.children=f}if(a&&a.defaultProps)for(m in l=a.defaultProps,l)void 0===d[m]&&(d[m]=l[m]);return{$$typeof:y,type:a,key:c,ref:h,props:d,_owner:L.current}}function oa(a,b){return{$$typeof:y,type:a.type,key:b,ref:a.ref,props:a.props,_owner:a._owner}}
function M(a){return"object"===typeof a&&null!==a&&a.$$typeof===y}function pa(a){var b={"=":"=0",":":"=2"};return"$"+a.replace(/[=:]/g,function(a){return b[a]})}function N(a,b){return"object"===typeof a&&null!==a&&null!=a.key?pa(""+a.key):b.toString(36)}function B(a,b,e,m,d){var c=typeof a;if("undefined"===c||"boolean"===c)a=null;var h=!1;if(null===a)h=!0;else switch(c){case "string":case "number":h=!0;break;case "object":switch(a.$$typeof){case y:case qa:h=!0}}if(h)return h=a,d=d(h),a=""===m?"."+
N(h,0):m,ca(d)?(e="",null!=a&&(e=a.replace(da,"$&/")+"/"),B(d,b,e,"",function(a){return a})):null!=d&&(M(d)&&(d=oa(d,e+(!d.key||h&&h.key===d.key?"":(""+d.key).replace(da,"$&/")+"/")+a)),b.push(d)),1;h=0;m=""===m?".":m+":";if(ca(a))for(var l=0;l<a.length;l++){c=a[l];var f=m+N(c,l);h+=B(c,b,e,f,d)}else if(f=x(a),"function"===typeof f)for(a=f.call(a),l=0;!(c=a.next()).done;)c=c.value,f=m+N(c,l++),h+=B(c,b,e,f,d);else if("object"===c)throw b=String(a),Error("Objects are not valid as a React child (found: "+
("[object Object]"===b?"object with keys {"+Object.keys(a).join(", ")+"}":b)+"). If you meant to render a collection of children, use an array instead.");return h}function C(a,b,e){if(null==a)return a;var c=[],d=0;B(a,c,"","",function(a){return b.call(e,a,d++)});return c}function ra(a){if(-1===a._status){var b=a._result;b=b();b.then(function(b){if(0===a._status||-1===a._status)a._status=1,a._result=b},function(b){if(0===a._status||-1===a._status)a._status=2,a._result=b});-1===a._status&&(a._status=
0,a._result=b)}if(1===a._status)return a._result.default;throw a._result;}function O(a,b){var e=a.length;a.push(b);a:for(;0<e;){var c=e-1>>>1,d=a[c];if(0<D(d,b))a[c]=b,a[e]=d,e=c;else break a}}function p(a){return 0===a.length?null:a[0]}function E(a){if(0===a.length)return null;var b=a[0],e=a.pop();if(e!==b){a[0]=e;a:for(var c=0,d=a.length,k=d>>>1;c<k;){var h=2*(c+1)-1,l=a[h],f=h+1,g=a[f];if(0>D(l,e))f<d&&0>D(g,l)?(a[c]=g,a[f]=e,c=f):(a[c]=l,a[h]=e,c=h);else if(f<d&&0>D(g,e))a[c]=g,a[f]=e,c=f;else break a}}return b}
function D(a,b){var c=a.sortIndex-b.sortIndex;return 0!==c?c:a.id-b.id}function P(a){for(var b=p(r);null!==b;){if(null===b.callback)E(r);else if(b.startTime<=a)E(r),b.sortIndex=b.expirationTime,O(q,b);else break;b=p(r)}}function Q(a){z=!1;P(a);if(!u)if(null!==p(q))u=!0,R(S);else{var b=p(r);null!==b&&T(Q,b.startTime-a)}}function S(a,b){u=!1;z&&(z=!1,ea(A),A=-1);F=!0;var c=k;try{P(b);for(n=p(q);null!==n&&(!(n.expirationTime>b)||a&&!fa());){var m=n.callback;if("function"===typeof m){n.callback=null;
k=n.priorityLevel;var d=m(n.expirationTime<=b);b=v();"function"===typeof d?n.callback=d:n===p(q)&&E(q);P(b)}else E(q);n=p(q)}if(null!==n)var g=!0;else{var h=p(r);null!==h&&T(Q,h.startTime-b);g=!1}return g}finally{n=null,k=c,F=!1}}function fa(){return v()-ha<ia?!1:!0}function R(a){G=a;H||(H=!0,I())}function T(a,b){A=ja(function(){a(v())},b)}function ka(a){throw Error("act(...) is not supported in production builds of React.");}var y=Symbol.for("react.element"),qa=Symbol.for("react.portal"),sa=Symbol.for("react.fragment"),
ta=Symbol.for("react.strict_mode"),ua=Symbol.for("react.profiler"),va=Symbol.for("react.provider"),wa=Symbol.for("react.context"),xa=Symbol.for("react.forward_ref"),ya=Symbol.for("react.suspense"),za=Symbol.for("react.memo"),Aa=Symbol.for("react.lazy"),V=Symbol.iterator,X={isMounted:function(a){return!1},enqueueForceUpdate:function(a,b,c){},enqueueReplaceState:function(a,b,c,m){},enqueueSetState:function(a,b,c,m){}},la=Object.assign,W={};w.prototype.isReactComponent={};w.prototype.setState=function(a,
b){if("object"!==typeof a&&"function"!==typeof a&&null!=a)throw Error("setState(...): takes an object of state variables to update or a function which returns an object of state variables.");this.updater.enqueueSetState(this,a,b,"setState")};w.prototype.forceUpdate=function(a){this.updater.enqueueForceUpdate(this,a,"forceUpdate")};Y.prototype=w.prototype;var t=K.prototype=new Y;t.constructor=K;la(t,w.prototype);t.isPureReactComponent=!0;var ca=Array.isArray,aa=Object.prototype.hasOwnProperty,L={current:null},
ba={key:!0,ref:!0,__self:!0,__source:!0},da=/\\/+/g,g={current:null},J={transition:null};if("object"===typeof performance&&"function"===typeof performance.now){var Ba=performance;var v=function(){return Ba.now()}}else{var ma=Date,Ca=ma.now();v=function(){return ma.now()-Ca}}var q=[],r=[],Da=1,n=null,k=3,F=!1,u=!1,z=!1,ja="function"===typeof setTimeout?setTimeout:null,ea="function"===typeof clearTimeout?clearTimeout:null,na="undefined"!==typeof setImmediate?setImmediate:null;"undefined"!==typeof navigator&&
void 0!==navigator.scheduling&&void 0!==navigator.scheduling.isInputPending&&navigator.scheduling.isInputPending.bind(navigator.scheduling);var H=!1,G=null,A=-1,ia=5,ha=-1,U=function(){if(null!==G){var a=v();ha=a;var b=!0;try{b=G(!0,a)}finally{b?I():(H=!1,G=null)}}else H=!1};if("function"===typeof na)var I=function(){na(U)};else if("undefined"!==typeof MessageChannel){t=new MessageChannel;var Ea=t.port2;t.port1.onmessage=U;I=function(){Ea.postMessage(null)}}else I=function(){ja(U,0)};t={ReactCurrentDispatcher:g,
ReactCurrentOwner:L,ReactCurrentBatchConfig:J,Scheduler:{__proto__:null,unstable_ImmediatePriority:1,unstable_UserBlockingPriority:2,unstable_NormalPriority:3,unstable_IdlePriority:5,unstable_LowPriority:4,unstable_runWithPriority:function(a,b){switch(a){case 1:case 2:case 3:case 4:case 5:break;default:a=3}var c=k;k=a;try{return b()}finally{k=c}},unstable_next:function(a){switch(k){case 1:case 2:case 3:var b=3;break;default:b=k}var c=k;k=b;try{return a()}finally{k=c}},unstable_scheduleCallback:function(a,
b,c){var e=v();"object"===typeof c&&null!==c?(c=c.delay,c="number"===typeof c&&0<c?e+c:e):c=e;switch(a){case 1:var d=-1;break;case 2:d=250;break;case 5:d=1073741823;break;case 4:d=1E4;break;default:d=5E3}d=c+d;a={id:Da++,callback:b,priorityLevel:a,startTime:c,expirationTime:d,sortIndex:-1};c>e?(a.sortIndex=c,O(r,a),null===p(q)&&a===p(r)&&(z?(ea(A),A=-1):z=!0,T(Q,c-e))):(a.sortIndex=d,O(q,a),u||F||(u=!0,R(S)));return a},unstable_cancelCallback:function(a){a.callback=null},unstable_wrapCallback:function(a){var b=
k;return function(){var c=k;k=b;try{return a.apply(this,arguments)}finally{k=c}}},unstable_getCurrentPriorityLevel:function(){return k},unstable_shouldYield:fa,unstable_requestPaint:function(){},unstable_continueExecution:function(){u||F||(u=!0,R(S))},unstable_pauseExecution:function(){},unstable_getFirstCallbackNode:function(){return p(q)},get unstable_now(){return v},unstable_forceFrameRate:function(a){0>a||125<a?console.error("forceFrameRate takes a positive int between 0 and 125, forcing frame rates higher than 125 fps is not supported"):
ia=0<a?Math.floor(1E3/a):5},unstable_Profiling:null}};c.Children={map:C,forEach:function(a,b,c){C(a,function(){b.apply(this,arguments)},c)},count:function(a){var b=0;C(a,function(){b++});return b},toArray:function(a){return C(a,function(a){return a})||[]},only:function(a){if(!M(a))throw Error("React.Children.only expected to receive a single React element child.");return a}};c.Component=w;c.Fragment=sa;c.Profiler=ua;c.PureComponent=K;c.StrictMode=ta;c.Suspense=ya;c.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED=
t;c.act=ka;c.cloneElement=function(a,b,c){if(null===a||void 0===a)throw Error("React.cloneElement(...): The argument must be a React element, but you passed "+a+".");var e=la({},a.props),d=a.key,k=a.ref,h=a._owner;if(null!=b){void 0!==b.ref&&(k=b.ref,h=L.current);void 0!==b.key&&(d=""+b.key);if(a.type&&a.type.defaultProps)var l=a.type.defaultProps;for(f in b)aa.call(b,f)&&!ba.hasOwnProperty(f)&&(e[f]=void 0===b[f]&&void 0!==l?l[f]:b[f])}var f=arguments.length-2;if(1===f)e.children=c;else if(1<f){l=
Array(f);for(var g=0;g<f;g++)l[g]=arguments[g+2];e.children=l}return{$$typeof:y,type:a.type,key:d,ref:k,props:e,_owner:h}};c.createContext=function(a){a={$$typeof:wa,_currentValue:a,_currentValue2:a,_threadCount:0,Provider:null,Consumer:null,_defaultValue:null,_globalName:null};a.Provider={$$typeof:va,_context:a};return a.Consumer=a};c.createElement=Z;c.createFactory=function(a){var b=Z.bind(null,a);b.type=a;return b};c.createRef=function(){return{current:null}};c.forwardRef=function(a){return{$$typeof:xa,
render:a}};c.isValidElement=M;c.lazy=function(a){return{$$typeof:Aa,_payload:{_status:-1,_result:a},_init:ra}};c.memo=function(a,b){return{$$typeof:za,type:a,compare:void 0===b?null:b}};c.startTransition=function(a,b){b=J.transition;J.transition={};try{a()}finally{J.transition=b}};c.unstable_act=ka;c.useCallback=function(a,b){return g.current.useCallback(a,b)};c.useContext=function(a){return g.current.useContext(a)};c.useDebugValue=function(a,b){};c.useDeferredValue=function(a){return g.current.useDeferredValue(a)};
c.useEffect=function(a,b){return g.current.useEffect(a,b)};c.useId=function(){return g.current.useId()};c.useImperativeHandle=function(a,b,c){return g.current.useImperativeHandle(a,b,c)};c.useInsertionEffect=function(a,b){return g.current.useInsertionEffect(a,b)};c.useLayoutEffect=function(a,b){return g.current.useLayoutEffect(a,b)};c.useMemo=function(a,b){return g.current.useMemo(a,b)};c.useReducer=function(a,b,c){return g.current.useReducer(a,b,c)};c.useRef=function(a){return g.current.useRef(a)};
c.useState=function(a){return g.current.useState(a)};c.useSyncExternalStore=function(a,b,c){return g.current.useSyncExternalStore(a,b,c)};c.useTransition=function(){return g.current.useTransition()};c.version="18.3.1"});
})();

</script>
<script>
/**
 * @license React
 * react-dom.production.min.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
(function(){/*
 Modernizr 3.0.0pre (Custom Build) | MIT
*/
'use strict';(function(Q,zb){"object"===typeof exports&&"undefined"!==typeof module?zb(exports,require("react")):"function"===typeof define&&define.amd?define(["exports","react"],zb):(Q=Q||self,zb(Q.ReactDOM={},Q.React))})(this,function(Q,zb){function m(a){for(var b="https://reactjs.org/docs/error-decoder.html?invariant="+a,c=1;c<arguments.length;c++)b+="&args[]="+encodeURIComponent(arguments[c]);return"Minified React error #"+a+"; visit "+b+" for the full message or use the non-minified dev environment for full errors and additional helpful warnings."}
function mb(a,b){Ab(a,b);Ab(a+"Capture",b)}function Ab(a,b){$b[a]=b;for(a=0;a<b.length;a++)cg.add(b[a])}function bj(a){if(Zd.call(dg,a))return!0;if(Zd.call(eg,a))return!1;if(cj.test(a))return dg[a]=!0;eg[a]=!0;return!1}function dj(a,b,c,d){if(null!==c&&0===c.type)return!1;switch(typeof b){case "function":case "symbol":return!0;case "boolean":if(d)return!1;if(null!==c)return!c.acceptsBooleans;a=a.toLowerCase().slice(0,5);return"data-"!==a&&"aria-"!==a;default:return!1}}function ej(a,b,c,d){if(null===
b||"undefined"===typeof b||dj(a,b,c,d))return!0;if(d)return!1;if(null!==c)switch(c.type){case 3:return!b;case 4:return!1===b;case 5:return isNaN(b);case 6:return isNaN(b)||1>b}return!1}function Y(a,b,c,d,e,f,g){this.acceptsBooleans=2===b||3===b||4===b;this.attributeName=d;this.attributeNamespace=e;this.mustUseProperty=c;this.propertyName=a;this.type=b;this.sanitizeURL=f;this.removeEmptyString=g}function $d(a,b,c,d){var e=R.hasOwnProperty(b)?R[b]:null;if(null!==e?0!==e.type:d||!(2<b.length)||"o"!==
b[0]&&"O"!==b[0]||"n"!==b[1]&&"N"!==b[1])ej(b,c,e,d)&&(c=null),d||null===e?bj(b)&&(null===c?a.removeAttribute(b):a.setAttribute(b,""+c)):e.mustUseProperty?a[e.propertyName]=null===c?3===e.type?!1:"":c:(b=e.attributeName,d=e.attributeNamespace,null===c?a.removeAttribute(b):(e=e.type,c=3===e||4===e&&!0===c?"":""+c,d?a.setAttributeNS(d,b,c):a.setAttribute(b,c)))}function ac(a){if(null===a||"object"!==typeof a)return null;a=fg&&a[fg]||a["@@iterator"];return"function"===typeof a?a:null}function bc(a,b,
c){if(void 0===ae)try{throw Error();}catch(d){ae=(b=d.stack.trim().match(/\\n( *(at )?)/))&&b[1]||""}return"\\n"+ae+a}function be(a,b){if(!a||ce)return"";ce=!0;var c=Error.prepareStackTrace;Error.prepareStackTrace=void 0;try{if(b)if(b=function(){throw Error();},Object.defineProperty(b.prototype,"props",{set:function(){throw Error();}}),"object"===typeof Reflect&&Reflect.construct){try{Reflect.construct(b,[])}catch(n){var d=n}Reflect.construct(a,[],b)}else{try{b.call()}catch(n){d=n}a.call(b.prototype)}else{try{throw Error();
}catch(n){d=n}a()}}catch(n){if(n&&d&&"string"===typeof n.stack){for(var e=n.stack.split("\\n"),f=d.stack.split("\\n"),g=e.length-1,h=f.length-1;1<=g&&0<=h&&e[g]!==f[h];)h--;for(;1<=g&&0<=h;g--,h--)if(e[g]!==f[h]){if(1!==g||1!==h){do if(g--,h--,0>h||e[g]!==f[h]){var k="\\n"+e[g].replace(" at new "," at ");a.displayName&&k.includes("<anonymous>")&&(k=k.replace("<anonymous>",a.displayName));return k}while(1<=g&&0<=h)}break}}}finally{ce=!1,Error.prepareStackTrace=c}return(a=a?a.displayName||a.name:"")?bc(a):
""}function fj(a){switch(a.tag){case 5:return bc(a.type);case 16:return bc("Lazy");case 13:return bc("Suspense");case 19:return bc("SuspenseList");case 0:case 2:case 15:return a=be(a.type,!1),a;case 11:return a=be(a.type.render,!1),a;case 1:return a=be(a.type,!0),a;default:return""}}function de(a){if(null==a)return null;if("function"===typeof a)return a.displayName||a.name||null;if("string"===typeof a)return a;switch(a){case Bb:return"Fragment";case Cb:return"Portal";case ee:return"Profiler";case fe:return"StrictMode";
case ge:return"Suspense";case he:return"SuspenseList"}if("object"===typeof a)switch(a.$$typeof){case gg:return(a.displayName||"Context")+".Consumer";case hg:return(a._context.displayName||"Context")+".Provider";case ie:var b=a.render;a=a.displayName;a||(a=b.displayName||b.name||"",a=""!==a?"ForwardRef("+a+")":"ForwardRef");return a;case je:return b=a.displayName||null,null!==b?b:de(a.type)||"Memo";case Ta:b=a._payload;a=a._init;try{return de(a(b))}catch(c){}}return null}function gj(a){var b=a.type;
switch(a.tag){case 24:return"Cache";case 9:return(b.displayName||"Context")+".Consumer";case 10:return(b._context.displayName||"Context")+".Provider";case 18:return"DehydratedFragment";case 11:return a=b.render,a=a.displayName||a.name||"",b.displayName||(""!==a?"ForwardRef("+a+")":"ForwardRef");case 7:return"Fragment";case 5:return b;case 4:return"Portal";case 3:return"Root";case 6:return"Text";case 16:return de(b);case 8:return b===fe?"StrictMode":"Mode";case 22:return"Offscreen";case 12:return"Profiler";
case 21:return"Scope";case 13:return"Suspense";case 19:return"SuspenseList";case 25:return"TracingMarker";case 1:case 0:case 17:case 2:case 14:case 15:if("function"===typeof b)return b.displayName||b.name||null;if("string"===typeof b)return b}return null}function Ua(a){switch(typeof a){case "boolean":case "number":case "string":case "undefined":return a;case "object":return a;default:return""}}function ig(a){var b=a.type;return(a=a.nodeName)&&"input"===a.toLowerCase()&&("checkbox"===b||"radio"===
b)}function hj(a){var b=ig(a)?"checked":"value",c=Object.getOwnPropertyDescriptor(a.constructor.prototype,b),d=""+a[b];if(!a.hasOwnProperty(b)&&"undefined"!==typeof c&&"function"===typeof c.get&&"function"===typeof c.set){var e=c.get,f=c.set;Object.defineProperty(a,b,{configurable:!0,get:function(){return e.call(this)},set:function(a){d=""+a;f.call(this,a)}});Object.defineProperty(a,b,{enumerable:c.enumerable});return{getValue:function(){return d},setValue:function(a){d=""+a},stopTracking:function(){a._valueTracker=
null;delete a[b]}}}}function Pc(a){a._valueTracker||(a._valueTracker=hj(a))}function jg(a){if(!a)return!1;var b=a._valueTracker;if(!b)return!0;var c=b.getValue();var d="";a&&(d=ig(a)?a.checked?"true":"false":a.value);a=d;return a!==c?(b.setValue(a),!0):!1}function Qc(a){a=a||("undefined"!==typeof document?document:void 0);if("undefined"===typeof a)return null;try{return a.activeElement||a.body}catch(b){return a.body}}function ke(a,b){var c=b.checked;return E({},b,{defaultChecked:void 0,defaultValue:void 0,
value:void 0,checked:null!=c?c:a._wrapperState.initialChecked})}function kg(a,b){var c=null==b.defaultValue?"":b.defaultValue,d=null!=b.checked?b.checked:b.defaultChecked;c=Ua(null!=b.value?b.value:c);a._wrapperState={initialChecked:d,initialValue:c,controlled:"checkbox"===b.type||"radio"===b.type?null!=b.checked:null!=b.value}}function lg(a,b){b=b.checked;null!=b&&$d(a,"checked",b,!1)}function le(a,b){lg(a,b);var c=Ua(b.value),d=b.type;if(null!=c)if("number"===d){if(0===c&&""===a.value||a.value!=
c)a.value=""+c}else a.value!==""+c&&(a.value=""+c);else if("submit"===d||"reset"===d){a.removeAttribute("value");return}b.hasOwnProperty("value")?me(a,b.type,c):b.hasOwnProperty("defaultValue")&&me(a,b.type,Ua(b.defaultValue));null==b.checked&&null!=b.defaultChecked&&(a.defaultChecked=!!b.defaultChecked)}function mg(a,b,c){if(b.hasOwnProperty("value")||b.hasOwnProperty("defaultValue")){var d=b.type;if(!("submit"!==d&&"reset"!==d||void 0!==b.value&&null!==b.value))return;b=""+a._wrapperState.initialValue;
c||b===a.value||(a.value=b);a.defaultValue=b}c=a.name;""!==c&&(a.name="");a.defaultChecked=!!a._wrapperState.initialChecked;""!==c&&(a.name=c)}function me(a,b,c){if("number"!==b||Qc(a.ownerDocument)!==a)null==c?a.defaultValue=""+a._wrapperState.initialValue:a.defaultValue!==""+c&&(a.defaultValue=""+c)}function Db(a,b,c,d){a=a.options;if(b){b={};for(var e=0;e<c.length;e++)b["$"+c[e]]=!0;for(c=0;c<a.length;c++)e=b.hasOwnProperty("$"+a[c].value),a[c].selected!==e&&(a[c].selected=e),e&&d&&(a[c].defaultSelected=
!0)}else{c=""+Ua(c);b=null;for(e=0;e<a.length;e++){if(a[e].value===c){a[e].selected=!0;d&&(a[e].defaultSelected=!0);return}null!==b||a[e].disabled||(b=a[e])}null!==b&&(b.selected=!0)}}function ne(a,b){if(null!=b.dangerouslySetInnerHTML)throw Error(m(91));return E({},b,{value:void 0,defaultValue:void 0,children:""+a._wrapperState.initialValue})}function ng(a,b){var c=b.value;if(null==c){c=b.children;b=b.defaultValue;if(null!=c){if(null!=b)throw Error(m(92));if(cc(c)){if(1<c.length)throw Error(m(93));
c=c[0]}b=c}null==b&&(b="");c=b}a._wrapperState={initialValue:Ua(c)}}function og(a,b){var c=Ua(b.value),d=Ua(b.defaultValue);null!=c&&(c=""+c,c!==a.value&&(a.value=c),null==b.defaultValue&&a.defaultValue!==c&&(a.defaultValue=c));null!=d&&(a.defaultValue=""+d)}function pg(a,b){b=a.textContent;b===a._wrapperState.initialValue&&""!==b&&null!==b&&(a.value=b)}function qg(a){switch(a){case "svg":return"http://www.w3.org/2000/svg";case "math":return"http://www.w3.org/1998/Math/MathML";default:return"http://www.w3.org/1999/xhtml"}}
function oe(a,b){return null==a||"http://www.w3.org/1999/xhtml"===a?qg(b):"http://www.w3.org/2000/svg"===a&&"foreignObject"===b?"http://www.w3.org/1999/xhtml":a}function rg(a,b,c){return null==b||"boolean"===typeof b||""===b?"":c||"number"!==typeof b||0===b||dc.hasOwnProperty(a)&&dc[a]?(""+b).trim():b+"px"}function sg(a,b){a=a.style;for(var c in b)if(b.hasOwnProperty(c)){var d=0===c.indexOf("--"),e=rg(c,b[c],d);"float"===c&&(c="cssFloat");d?a.setProperty(c,e):a[c]=e}}function pe(a,b){if(b){if(ij[a]&&
(null!=b.children||null!=b.dangerouslySetInnerHTML))throw Error(m(137,a));if(null!=b.dangerouslySetInnerHTML){if(null!=b.children)throw Error(m(60));if("object"!==typeof b.dangerouslySetInnerHTML||!("__html"in b.dangerouslySetInnerHTML))throw Error(m(61));}if(null!=b.style&&"object"!==typeof b.style)throw Error(m(62));}}function qe(a,b){if(-1===a.indexOf("-"))return"string"===typeof b.is;switch(a){case "annotation-xml":case "color-profile":case "font-face":case "font-face-src":case "font-face-uri":case "font-face-format":case "font-face-name":case "missing-glyph":return!1;
default:return!0}}function re(a){a=a.target||a.srcElement||window;a.correspondingUseElement&&(a=a.correspondingUseElement);return 3===a.nodeType?a.parentNode:a}function tg(a){if(a=ec(a)){if("function"!==typeof se)throw Error(m(280));var b=a.stateNode;b&&(b=Rc(b),se(a.stateNode,a.type,b))}}function ug(a){Eb?Fb?Fb.push(a):Fb=[a]:Eb=a}function vg(){if(Eb){var a=Eb,b=Fb;Fb=Eb=null;tg(a);if(b)for(a=0;a<b.length;a++)tg(b[a])}}function wg(a,b,c){if(te)return a(b,c);te=!0;try{return xg(a,b,c)}finally{if(te=
!1,null!==Eb||null!==Fb)yg(),vg()}}function fc(a,b){var c=a.stateNode;if(null===c)return null;var d=Rc(c);if(null===d)return null;c=d[b];a:switch(b){case "onClick":case "onClickCapture":case "onDoubleClick":case "onDoubleClickCapture":case "onMouseDown":case "onMouseDownCapture":case "onMouseMove":case "onMouseMoveCapture":case "onMouseUp":case "onMouseUpCapture":case "onMouseEnter":(d=!d.disabled)||(a=a.type,d=!("button"===a||"input"===a||"select"===a||"textarea"===a));a=!d;break a;default:a=!1}if(a)return null;
if(c&&"function"!==typeof c)throw Error(m(231,b,typeof c));return c}function jj(a,b,c,d,e,f,g,h,k){gc=!1;Sc=null;kj.apply(lj,arguments)}function mj(a,b,c,d,e,f,g,h,k){jj.apply(this,arguments);if(gc){if(gc){var n=Sc;gc=!1;Sc=null}else throw Error(m(198));Tc||(Tc=!0,ue=n)}}function nb(a){var b=a,c=a;if(a.alternate)for(;b.return;)b=b.return;else{a=b;do b=a,0!==(b.flags&4098)&&(c=b.return),a=b.return;while(a)}return 3===b.tag?c:null}function zg(a){if(13===a.tag){var b=a.memoizedState;null===b&&(a=a.alternate,
null!==a&&(b=a.memoizedState));if(null!==b)return b.dehydrated}return null}function Ag(a){if(nb(a)!==a)throw Error(m(188));}function nj(a){var b=a.alternate;if(!b){b=nb(a);if(null===b)throw Error(m(188));return b!==a?null:a}for(var c=a,d=b;;){var e=c.return;if(null===e)break;var f=e.alternate;if(null===f){d=e.return;if(null!==d){c=d;continue}break}if(e.child===f.child){for(f=e.child;f;){if(f===c)return Ag(e),a;if(f===d)return Ag(e),b;f=f.sibling}throw Error(m(188));}if(c.return!==d.return)c=e,d=f;
else{for(var g=!1,h=e.child;h;){if(h===c){g=!0;c=e;d=f;break}if(h===d){g=!0;d=e;c=f;break}h=h.sibling}if(!g){for(h=f.child;h;){if(h===c){g=!0;c=f;d=e;break}if(h===d){g=!0;d=f;c=e;break}h=h.sibling}if(!g)throw Error(m(189));}}if(c.alternate!==d)throw Error(m(190));}if(3!==c.tag)throw Error(m(188));return c.stateNode.current===c?a:b}function Bg(a){a=nj(a);return null!==a?Cg(a):null}function Cg(a){if(5===a.tag||6===a.tag)return a;for(a=a.child;null!==a;){var b=Cg(a);if(null!==b)return b;a=a.sibling}return null}
function oj(a,b){if(Ca&&"function"===typeof Ca.onCommitFiberRoot)try{Ca.onCommitFiberRoot(Uc,a,void 0,128===(a.current.flags&128))}catch(c){}}function pj(a){a>>>=0;return 0===a?32:31-(qj(a)/rj|0)|0}function hc(a){switch(a&-a){case 1:return 1;case 2:return 2;case 4:return 4;case 8:return 8;case 16:return 16;case 32:return 32;case 64:case 128:case 256:case 512:case 1024:case 2048:case 4096:case 8192:case 16384:case 32768:case 65536:case 131072:case 262144:case 524288:case 1048576:case 2097152:return a&
4194240;case 4194304:case 8388608:case 16777216:case 33554432:case 67108864:return a&130023424;case 134217728:return 134217728;case 268435456:return 268435456;case 536870912:return 536870912;case 1073741824:return 1073741824;default:return a}}function Vc(a,b){var c=a.pendingLanes;if(0===c)return 0;var d=0,e=a.suspendedLanes,f=a.pingedLanes,g=c&268435455;if(0!==g){var h=g&~e;0!==h?d=hc(h):(f&=g,0!==f&&(d=hc(f)))}else g=c&~e,0!==g?d=hc(g):0!==f&&(d=hc(f));if(0===d)return 0;if(0!==b&&b!==d&&0===(b&e)&&
(e=d&-d,f=b&-b,e>=f||16===e&&0!==(f&4194240)))return b;0!==(d&4)&&(d|=c&16);b=a.entangledLanes;if(0!==b)for(a=a.entanglements,b&=d;0<b;)c=31-ta(b),e=1<<c,d|=a[c],b&=~e;return d}function sj(a,b){switch(a){case 1:case 2:case 4:return b+250;case 8:case 16:case 32:case 64:case 128:case 256:case 512:case 1024:case 2048:case 4096:case 8192:case 16384:case 32768:case 65536:case 131072:case 262144:case 524288:case 1048576:case 2097152:return b+5E3;case 4194304:case 8388608:case 16777216:case 33554432:case 67108864:return-1;
case 134217728:case 268435456:case 536870912:case 1073741824:return-1;default:return-1}}function tj(a,b){for(var c=a.suspendedLanes,d=a.pingedLanes,e=a.expirationTimes,f=a.pendingLanes;0<f;){var g=31-ta(f),h=1<<g,k=e[g];if(-1===k){if(0===(h&c)||0!==(h&d))e[g]=sj(h,b)}else k<=b&&(a.expiredLanes|=h);f&=~h}}function ve(a){a=a.pendingLanes&-1073741825;return 0!==a?a:a&1073741824?1073741824:0}function Dg(){var a=Wc;Wc<<=1;0===(Wc&4194240)&&(Wc=64);return a}function we(a){for(var b=[],c=0;31>c;c++)b.push(a);
return b}function ic(a,b,c){a.pendingLanes|=b;536870912!==b&&(a.suspendedLanes=0,a.pingedLanes=0);a=a.eventTimes;b=31-ta(b);a[b]=c}function uj(a,b){var c=a.pendingLanes&~b;a.pendingLanes=b;a.suspendedLanes=0;a.pingedLanes=0;a.expiredLanes&=b;a.mutableReadLanes&=b;a.entangledLanes&=b;b=a.entanglements;var d=a.eventTimes;for(a=a.expirationTimes;0<c;){var e=31-ta(c),f=1<<e;b[e]=0;d[e]=-1;a[e]=-1;c&=~f}}function xe(a,b){var c=a.entangledLanes|=b;for(a=a.entanglements;c;){var d=31-ta(c),e=1<<d;e&b|a[d]&
b&&(a[d]|=b);c&=~e}}function Eg(a){a&=-a;return 1<a?4<a?0!==(a&268435455)?16:536870912:4:1}function Fg(a,b){switch(a){case "focusin":case "focusout":Va=null;break;case "dragenter":case "dragleave":Wa=null;break;case "mouseover":case "mouseout":Xa=null;break;case "pointerover":case "pointerout":jc.delete(b.pointerId);break;case "gotpointercapture":case "lostpointercapture":kc.delete(b.pointerId)}}function lc(a,b,c,d,e,f){if(null===a||a.nativeEvent!==f)return a={blockedOn:b,domEventName:c,eventSystemFlags:d,
nativeEvent:f,targetContainers:[e]},null!==b&&(b=ec(b),null!==b&&Gg(b)),a;a.eventSystemFlags|=d;b=a.targetContainers;null!==e&&-1===b.indexOf(e)&&b.push(e);return a}function vj(a,b,c,d,e){switch(b){case "focusin":return Va=lc(Va,a,b,c,d,e),!0;case "dragenter":return Wa=lc(Wa,a,b,c,d,e),!0;case "mouseover":return Xa=lc(Xa,a,b,c,d,e),!0;case "pointerover":var f=e.pointerId;jc.set(f,lc(jc.get(f)||null,a,b,c,d,e));return!0;case "gotpointercapture":return f=e.pointerId,kc.set(f,lc(kc.get(f)||null,a,b,
c,d,e)),!0}return!1}function Hg(a){var b=ob(a.target);if(null!==b){var c=nb(b);if(null!==c)if(b=c.tag,13===b){if(b=zg(c),null!==b){a.blockedOn=b;wj(a.priority,function(){xj(c)});return}}else if(3===b&&c.stateNode.current.memoizedState.isDehydrated){a.blockedOn=3===c.tag?c.stateNode.containerInfo:null;return}}a.blockedOn=null}function Xc(a){if(null!==a.blockedOn)return!1;for(var b=a.targetContainers;0<b.length;){var c=ye(a.domEventName,a.eventSystemFlags,b[0],a.nativeEvent);if(null===c){c=a.nativeEvent;
var d=new c.constructor(c.type,c);ze=d;c.target.dispatchEvent(d);ze=null}else return b=ec(c),null!==b&&Gg(b),a.blockedOn=c,!1;b.shift()}return!0}function Ig(a,b,c){Xc(a)&&c.delete(b)}function yj(){Ae=!1;null!==Va&&Xc(Va)&&(Va=null);null!==Wa&&Xc(Wa)&&(Wa=null);null!==Xa&&Xc(Xa)&&(Xa=null);jc.forEach(Ig);kc.forEach(Ig)}function mc(a,b){a.blockedOn===b&&(a.blockedOn=null,Ae||(Ae=!0,Jg(Kg,yj)))}function nc(a){if(0<Yc.length){mc(Yc[0],a);for(var b=1;b<Yc.length;b++){var c=Yc[b];c.blockedOn===a&&(c.blockedOn=
null)}}null!==Va&&mc(Va,a);null!==Wa&&mc(Wa,a);null!==Xa&&mc(Xa,a);b=function(b){return mc(b,a)};jc.forEach(b);kc.forEach(b);for(b=0;b<Ya.length;b++)c=Ya[b],c.blockedOn===a&&(c.blockedOn=null);for(;0<Ya.length&&(b=Ya[0],null===b.blockedOn);)Hg(b),null===b.blockedOn&&Ya.shift()}function zj(a,b,c,d){var e=z,f=Gb.transition;Gb.transition=null;try{z=1,Be(a,b,c,d)}finally{z=e,Gb.transition=f}}function Aj(a,b,c,d){var e=z,f=Gb.transition;Gb.transition=null;try{z=4,Be(a,b,c,d)}finally{z=e,Gb.transition=
f}}function Be(a,b,c,d){if(Zc){var e=ye(a,b,c,d);if(null===e)Ce(a,b,d,$c,c),Fg(a,d);else if(vj(e,a,b,c,d))d.stopPropagation();else if(Fg(a,d),b&4&&-1<Bj.indexOf(a)){for(;null!==e;){var f=ec(e);null!==f&&Cj(f);f=ye(a,b,c,d);null===f&&Ce(a,b,d,$c,c);if(f===e)break;e=f}null!==e&&d.stopPropagation()}else Ce(a,b,d,null,c)}}function ye(a,b,c,d){$c=null;a=re(d);a=ob(a);if(null!==a)if(b=nb(a),null===b)a=null;else if(c=b.tag,13===c){a=zg(b);if(null!==a)return a;a=null}else if(3===c){if(b.stateNode.current.memoizedState.isDehydrated)return 3===
b.tag?b.stateNode.containerInfo:null;a=null}else b!==a&&(a=null);$c=a;return null}function Lg(a){switch(a){case "cancel":case "click":case "close":case "contextmenu":case "copy":case "cut":case "auxclick":case "dblclick":case "dragend":case "dragstart":case "drop":case "focusin":case "focusout":case "input":case "invalid":case "keydown":case "keypress":case "keyup":case "mousedown":case "mouseup":case "paste":case "pause":case "play":case "pointercancel":case "pointerdown":case "pointerup":case "ratechange":case "reset":case "resize":case "seeked":case "submit":case "touchcancel":case "touchend":case "touchstart":case "volumechange":case "change":case "selectionchange":case "textInput":case "compositionstart":case "compositionend":case "compositionupdate":case "beforeblur":case "afterblur":case "beforeinput":case "blur":case "fullscreenchange":case "focus":case "hashchange":case "popstate":case "select":case "selectstart":return 1;
case "drag":case "dragenter":case "dragexit":case "dragleave":case "dragover":case "mousemove":case "mouseout":case "mouseover":case "pointermove":case "pointerout":case "pointerover":case "scroll":case "toggle":case "touchmove":case "wheel":case "mouseenter":case "mouseleave":case "pointerenter":case "pointerleave":return 4;case "message":switch(Dj()){case De:return 1;case Mg:return 4;case ad:case Ej:return 16;case Ng:return 536870912;default:return 16}default:return 16}}function Og(){if(bd)return bd;
var a,b=Ee,c=b.length,d,e="value"in Za?Za.value:Za.textContent,f=e.length;for(a=0;a<c&&b[a]===e[a];a++);var g=c-a;for(d=1;d<=g&&b[c-d]===e[f-d];d++);return bd=e.slice(a,1<d?1-d:void 0)}function cd(a){var b=a.keyCode;"charCode"in a?(a=a.charCode,0===a&&13===b&&(a=13)):a=b;10===a&&(a=13);return 32<=a||13===a?a:0}function dd(){return!0}function Pg(){return!1}function ka(a){function b(b,d,e,f,g){this._reactName=b;this._targetInst=e;this.type=d;this.nativeEvent=f;this.target=g;this.currentTarget=null;
for(var c in a)a.hasOwnProperty(c)&&(b=a[c],this[c]=b?b(f):f[c]);this.isDefaultPrevented=(null!=f.defaultPrevented?f.defaultPrevented:!1===f.returnValue)?dd:Pg;this.isPropagationStopped=Pg;return this}E(b.prototype,{preventDefault:function(){this.defaultPrevented=!0;var a=this.nativeEvent;a&&(a.preventDefault?a.preventDefault():"unknown"!==typeof a.returnValue&&(a.returnValue=!1),this.isDefaultPrevented=dd)},stopPropagation:function(){var a=this.nativeEvent;a&&(a.stopPropagation?a.stopPropagation():
"unknown"!==typeof a.cancelBubble&&(a.cancelBubble=!0),this.isPropagationStopped=dd)},persist:function(){},isPersistent:dd});return b}function Fj(a){var b=this.nativeEvent;return b.getModifierState?b.getModifierState(a):(a=Gj[a])?!!b[a]:!1}function Fe(a){return Fj}function Qg(a,b){switch(a){case "keyup":return-1!==Hj.indexOf(b.keyCode);case "keydown":return 229!==b.keyCode;case "keypress":case "mousedown":case "focusout":return!0;default:return!1}}function Rg(a){a=a.detail;return"object"===typeof a&&
"data"in a?a.data:null}function Ij(a,b){switch(a){case "compositionend":return Rg(b);case "keypress":if(32!==b.which)return null;Sg=!0;return Tg;case "textInput":return a=b.data,a===Tg&&Sg?null:a;default:return null}}function Jj(a,b){if(Hb)return"compositionend"===a||!Ge&&Qg(a,b)?(a=Og(),bd=Ee=Za=null,Hb=!1,a):null;switch(a){case "paste":return null;case "keypress":if(!(b.ctrlKey||b.altKey||b.metaKey)||b.ctrlKey&&b.altKey){if(b.char&&1<b.char.length)return b.char;if(b.which)return String.fromCharCode(b.which)}return null;
case "compositionend":return Ug&&"ko"!==b.locale?null:b.data;default:return null}}function Vg(a){var b=a&&a.nodeName&&a.nodeName.toLowerCase();return"input"===b?!!Kj[a.type]:"textarea"===b?!0:!1}function Lj(a){if(!Ia)return!1;a="on"+a;var b=a in document;b||(b=document.createElement("div"),b.setAttribute(a,"return;"),b="function"===typeof b[a]);return b}function Wg(a,b,c,d){ug(d);b=ed(b,"onChange");0<b.length&&(c=new He("onChange","change",null,c,d),a.push({event:c,listeners:b}))}function Mj(a){Xg(a,
0)}function fd(a){var b=Ib(a);if(jg(b))return a}function Nj(a,b){if("change"===a)return b}function Yg(){oc&&(oc.detachEvent("onpropertychange",Zg),pc=oc=null)}function Zg(a){if("value"===a.propertyName&&fd(pc)){var b=[];Wg(b,pc,a,re(a));wg(Mj,b)}}function Oj(a,b,c){"focusin"===a?(Yg(),oc=b,pc=c,oc.attachEvent("onpropertychange",Zg)):"focusout"===a&&Yg()}function Pj(a,b){if("selectionchange"===a||"keyup"===a||"keydown"===a)return fd(pc)}function Qj(a,b){if("click"===a)return fd(b)}function Rj(a,b){if("input"===
a||"change"===a)return fd(b)}function Sj(a,b){return a===b&&(0!==a||1/a===1/b)||a!==a&&b!==b}function qc(a,b){if(ua(a,b))return!0;if("object"!==typeof a||null===a||"object"!==typeof b||null===b)return!1;var c=Object.keys(a),d=Object.keys(b);if(c.length!==d.length)return!1;for(d=0;d<c.length;d++){var e=c[d];if(!Zd.call(b,e)||!ua(a[e],b[e]))return!1}return!0}function $g(a){for(;a&&a.firstChild;)a=a.firstChild;return a}function ah(a,b){var c=$g(a);a=0;for(var d;c;){if(3===c.nodeType){d=a+c.textContent.length;
if(a<=b&&d>=b)return{node:c,offset:b-a};a=d}a:{for(;c;){if(c.nextSibling){c=c.nextSibling;break a}c=c.parentNode}c=void 0}c=$g(c)}}function bh(a,b){return a&&b?a===b?!0:a&&3===a.nodeType?!1:b&&3===b.nodeType?bh(a,b.parentNode):"contains"in a?a.contains(b):a.compareDocumentPosition?!!(a.compareDocumentPosition(b)&16):!1:!1}function ch(){for(var a=window,b=Qc();b instanceof a.HTMLIFrameElement;){try{var c="string"===typeof b.contentWindow.location.href}catch(d){c=!1}if(c)a=b.contentWindow;else break;
b=Qc(a.document)}return b}function Ie(a){var b=a&&a.nodeName&&a.nodeName.toLowerCase();return b&&("input"===b&&("text"===a.type||"search"===a.type||"tel"===a.type||"url"===a.type||"password"===a.type)||"textarea"===b||"true"===a.contentEditable)}function Tj(a){var b=ch(),c=a.focusedElem,d=a.selectionRange;if(b!==c&&c&&c.ownerDocument&&bh(c.ownerDocument.documentElement,c)){if(null!==d&&Ie(c))if(b=d.start,a=d.end,void 0===a&&(a=b),"selectionStart"in c)c.selectionStart=b,c.selectionEnd=Math.min(a,c.value.length);
else if(a=(b=c.ownerDocument||document)&&b.defaultView||window,a.getSelection){a=a.getSelection();var e=c.textContent.length,f=Math.min(d.start,e);d=void 0===d.end?f:Math.min(d.end,e);!a.extend&&f>d&&(e=d,d=f,f=e);e=ah(c,f);var g=ah(c,d);e&&g&&(1!==a.rangeCount||a.anchorNode!==e.node||a.anchorOffset!==e.offset||a.focusNode!==g.node||a.focusOffset!==g.offset)&&(b=b.createRange(),b.setStart(e.node,e.offset),a.removeAllRanges(),f>d?(a.addRange(b),a.extend(g.node,g.offset)):(b.setEnd(g.node,g.offset),
a.addRange(b)))}b=[];for(a=c;a=a.parentNode;)1===a.nodeType&&b.push({element:a,left:a.scrollLeft,top:a.scrollTop});"function"===typeof c.focus&&c.focus();for(c=0;c<b.length;c++)a=b[c],a.element.scrollLeft=a.left,a.element.scrollTop=a.top}}function dh(a,b,c){var d=c.window===c?c.document:9===c.nodeType?c:c.ownerDocument;Je||null==Jb||Jb!==Qc(d)||(d=Jb,"selectionStart"in d&&Ie(d)?d={start:d.selectionStart,end:d.selectionEnd}:(d=(d.ownerDocument&&d.ownerDocument.defaultView||window).getSelection(),d=
{anchorNode:d.anchorNode,anchorOffset:d.anchorOffset,focusNode:d.focusNode,focusOffset:d.focusOffset}),rc&&qc(rc,d)||(rc=d,d=ed(Ke,"onSelect"),0<d.length&&(b=new He("onSelect","select",null,b,c),a.push({event:b,listeners:d}),b.target=Jb)))}function gd(a,b){var c={};c[a.toLowerCase()]=b.toLowerCase();c["Webkit"+a]="webkit"+b;c["Moz"+a]="moz"+b;return c}function hd(a){if(Le[a])return Le[a];if(!Kb[a])return a;var b=Kb[a],c;for(c in b)if(b.hasOwnProperty(c)&&c in eh)return Le[a]=b[c];return a}function $a(a,
b){fh.set(a,b);mb(b,[a])}function gh(a,b,c){var d=a.type||"unknown-event";a.currentTarget=c;mj(d,b,void 0,a);a.currentTarget=null}function Xg(a,b){b=0!==(b&4);for(var c=0;c<a.length;c++){var d=a[c],e=d.event;d=d.listeners;a:{var f=void 0;if(b)for(var g=d.length-1;0<=g;g--){var h=d[g],k=h.instance,n=h.currentTarget;h=h.listener;if(k!==f&&e.isPropagationStopped())break a;gh(e,h,n);f=k}else for(g=0;g<d.length;g++){h=d[g];k=h.instance;n=h.currentTarget;h=h.listener;if(k!==f&&e.isPropagationStopped())break a;
gh(e,h,n);f=k}}}if(Tc)throw a=ue,Tc=!1,ue=null,a;}function B(a,b){var c=b[Me];void 0===c&&(c=b[Me]=new Set);var d=a+"__bubble";c.has(d)||(hh(b,a,2,!1),c.add(d))}function Ne(a,b,c){var d=0;b&&(d|=4);hh(c,a,d,b)}function sc(a){if(!a[id]){a[id]=!0;cg.forEach(function(b){"selectionchange"!==b&&(Uj.has(b)||Ne(b,!1,a),Ne(b,!0,a))});var b=9===a.nodeType?a:a.ownerDocument;null===b||b[id]||(b[id]=!0,Ne("selectionchange",!1,b))}}function hh(a,b,c,d,e){switch(Lg(b)){case 1:e=zj;break;case 4:e=Aj;break;default:e=
Be}c=e.bind(null,b,c,a);e=void 0;!Oe||"touchstart"!==b&&"touchmove"!==b&&"wheel"!==b||(e=!0);d?void 0!==e?a.addEventListener(b,c,{capture:!0,passive:e}):a.addEventListener(b,c,!0):void 0!==e?a.addEventListener(b,c,{passive:e}):a.addEventListener(b,c,!1)}function Ce(a,b,c,d,e){var f=d;if(0===(b&1)&&0===(b&2)&&null!==d)a:for(;;){if(null===d)return;var g=d.tag;if(3===g||4===g){var h=d.stateNode.containerInfo;if(h===e||8===h.nodeType&&h.parentNode===e)break;if(4===g)for(g=d.return;null!==g;){var k=g.tag;
if(3===k||4===k)if(k=g.stateNode.containerInfo,k===e||8===k.nodeType&&k.parentNode===e)return;g=g.return}for(;null!==h;){g=ob(h);if(null===g)return;k=g.tag;if(5===k||6===k){d=f=g;continue a}h=h.parentNode}}d=d.return}wg(function(){var d=f,e=re(c),g=[];a:{var h=fh.get(a);if(void 0!==h){var k=He,m=a;switch(a){case "keypress":if(0===cd(c))break a;case "keydown":case "keyup":k=Vj;break;case "focusin":m="focus";k=Pe;break;case "focusout":m="blur";k=Pe;break;case "beforeblur":case "afterblur":k=Pe;break;
case "click":if(2===c.button)break a;case "auxclick":case "dblclick":case "mousedown":case "mousemove":case "mouseup":case "mouseout":case "mouseover":case "contextmenu":k=ih;break;case "drag":case "dragend":case "dragenter":case "dragexit":case "dragleave":case "dragover":case "dragstart":case "drop":k=Wj;break;case "touchcancel":case "touchend":case "touchmove":case "touchstart":k=Xj;break;case jh:case kh:case lh:k=Yj;break;case mh:k=Zj;break;case "scroll":k=ak;break;case "wheel":k=bk;break;case "copy":case "cut":case "paste":k=
ck;break;case "gotpointercapture":case "lostpointercapture":case "pointercancel":case "pointerdown":case "pointermove":case "pointerout":case "pointerover":case "pointerup":k=nh}var l=0!==(b&4),p=!l&&"scroll"===a,w=l?null!==h?h+"Capture":null:h;l=[];for(var A=d,t;null!==A;){t=A;var M=t.stateNode;5===t.tag&&null!==M&&(t=M,null!==w&&(M=fc(A,w),null!=M&&l.push(tc(A,M,t))));if(p)break;A=A.return}0<l.length&&(h=new k(h,m,null,c,e),g.push({event:h,listeners:l}))}}if(0===(b&7)){a:{h="mouseover"===a||"pointerover"===
a;k="mouseout"===a||"pointerout"===a;if(h&&c!==ze&&(m=c.relatedTarget||c.fromElement)&&(ob(m)||m[Ja]))break a;if(k||h){h=e.window===e?e:(h=e.ownerDocument)?h.defaultView||h.parentWindow:window;if(k){if(m=c.relatedTarget||c.toElement,k=d,m=m?ob(m):null,null!==m&&(p=nb(m),m!==p||5!==m.tag&&6!==m.tag))m=null}else k=null,m=d;if(k!==m){l=ih;M="onMouseLeave";w="onMouseEnter";A="mouse";if("pointerout"===a||"pointerover"===a)l=nh,M="onPointerLeave",w="onPointerEnter",A="pointer";p=null==k?h:Ib(k);t=null==
m?h:Ib(m);h=new l(M,A+"leave",k,c,e);h.target=p;h.relatedTarget=t;M=null;ob(e)===d&&(l=new l(w,A+"enter",m,c,e),l.target=t,l.relatedTarget=p,M=l);p=M;if(k&&m)b:{l=k;w=m;A=0;for(t=l;t;t=Lb(t))A++;t=0;for(M=w;M;M=Lb(M))t++;for(;0<A-t;)l=Lb(l),A--;for(;0<t-A;)w=Lb(w),t--;for(;A--;){if(l===w||null!==w&&l===w.alternate)break b;l=Lb(l);w=Lb(w)}l=null}else l=null;null!==k&&oh(g,h,k,l,!1);null!==m&&null!==p&&oh(g,p,m,l,!0)}}}a:{h=d?Ib(d):window;k=h.nodeName&&h.nodeName.toLowerCase();if("select"===k||"input"===
k&&"file"===h.type)var ma=Nj;else if(Vg(h))if(ph)ma=Rj;else{ma=Pj;var va=Oj}else(k=h.nodeName)&&"input"===k.toLowerCase()&&("checkbox"===h.type||"radio"===h.type)&&(ma=Qj);if(ma&&(ma=ma(a,d))){Wg(g,ma,c,e);break a}va&&va(a,h,d);"focusout"===a&&(va=h._wrapperState)&&va.controlled&&"number"===h.type&&me(h,"number",h.value)}va=d?Ib(d):window;switch(a){case "focusin":if(Vg(va)||"true"===va.contentEditable)Jb=va,Ke=d,rc=null;break;case "focusout":rc=Ke=Jb=null;break;case "mousedown":Je=!0;break;case "contextmenu":case "mouseup":case "dragend":Je=
!1;dh(g,c,e);break;case "selectionchange":if(dk)break;case "keydown":case "keyup":dh(g,c,e)}var ab;if(Ge)b:{switch(a){case "compositionstart":var da="onCompositionStart";break b;case "compositionend":da="onCompositionEnd";break b;case "compositionupdate":da="onCompositionUpdate";break b}da=void 0}else Hb?Qg(a,c)&&(da="onCompositionEnd"):"keydown"===a&&229===c.keyCode&&(da="onCompositionStart");da&&(Ug&&"ko"!==c.locale&&(Hb||"onCompositionStart"!==da?"onCompositionEnd"===da&&Hb&&(ab=Og()):(Za=e,Ee=
"value"in Za?Za.value:Za.textContent,Hb=!0)),va=ed(d,da),0<va.length&&(da=new qh(da,a,null,c,e),g.push({event:da,listeners:va}),ab?da.data=ab:(ab=Rg(c),null!==ab&&(da.data=ab))));if(ab=ek?Ij(a,c):Jj(a,c))d=ed(d,"onBeforeInput"),0<d.length&&(e=new fk("onBeforeInput","beforeinput",null,c,e),g.push({event:e,listeners:d}),e.data=ab)}Xg(g,b)})}function tc(a,b,c){return{instance:a,listener:b,currentTarget:c}}function ed(a,b){for(var c=b+"Capture",d=[];null!==a;){var e=a,f=e.stateNode;5===e.tag&&null!==
f&&(e=f,f=fc(a,c),null!=f&&d.unshift(tc(a,f,e)),f=fc(a,b),null!=f&&d.push(tc(a,f,e)));a=a.return}return d}function Lb(a){if(null===a)return null;do a=a.return;while(a&&5!==a.tag);return a?a:null}function oh(a,b,c,d,e){for(var f=b._reactName,g=[];null!==c&&c!==d;){var h=c,k=h.alternate,n=h.stateNode;if(null!==k&&k===d)break;5===h.tag&&null!==n&&(h=n,e?(k=fc(c,f),null!=k&&g.unshift(tc(c,k,h))):e||(k=fc(c,f),null!=k&&g.push(tc(c,k,h))));c=c.return}0!==g.length&&a.push({event:b,listeners:g})}function rh(a){return("string"===
typeof a?a:""+a).replace(gk,"\\n").replace(hk,"")}function jd(a,b,c,d){b=rh(b);if(rh(a)!==b&&c)throw Error(m(425));}function kd(){}function Qe(a,b){return"textarea"===a||"noscript"===a||"string"===typeof b.children||"number"===typeof b.children||"object"===typeof b.dangerouslySetInnerHTML&&null!==b.dangerouslySetInnerHTML&&null!=b.dangerouslySetInnerHTML.__html}function ik(a){setTimeout(function(){throw a;})}function Re(a,b){var c=b,d=0;do{var e=c.nextSibling;a.removeChild(c);if(e&&8===e.nodeType)if(c=
e.data,"/$"===c){if(0===d){a.removeChild(e);nc(b);return}d--}else"$"!==c&&"$?"!==c&&"$!"!==c||d++;c=e}while(c);nc(b)}function Ka(a){for(;null!=a;a=a.nextSibling){var b=a.nodeType;if(1===b||3===b)break;if(8===b){b=a.data;if("$"===b||"$!"===b||"$?"===b)break;if("/$"===b)return null}}return a}function sh(a){a=a.previousSibling;for(var b=0;a;){if(8===a.nodeType){var c=a.data;if("$"===c||"$!"===c||"$?"===c){if(0===b)return a;b--}else"/$"===c&&b++}a=a.previousSibling}return null}function ob(a){var b=a[Da];
if(b)return b;for(var c=a.parentNode;c;){if(b=c[Ja]||c[Da]){c=b.alternate;if(null!==b.child||null!==c&&null!==c.child)for(a=sh(a);null!==a;){if(c=a[Da])return c;a=sh(a)}return b}a=c;c=a.parentNode}return null}function ec(a){a=a[Da]||a[Ja];return!a||5!==a.tag&&6!==a.tag&&13!==a.tag&&3!==a.tag?null:a}function Ib(a){if(5===a.tag||6===a.tag)return a.stateNode;throw Error(m(33));}function Rc(a){return a[uc]||null}function bb(a){return{current:a}}function v(a,b){0>Mb||(a.current=Se[Mb],Se[Mb]=null,Mb--)}
function y(a,b,c){Mb++;Se[Mb]=a.current;a.current=b}function Nb(a,b){var c=a.type.contextTypes;if(!c)return cb;var d=a.stateNode;if(d&&d.__reactInternalMemoizedUnmaskedChildContext===b)return d.__reactInternalMemoizedMaskedChildContext;var e={},f;for(f in c)e[f]=b[f];d&&(a=a.stateNode,a.__reactInternalMemoizedUnmaskedChildContext=b,a.__reactInternalMemoizedMaskedChildContext=e);return e}function ea(a){a=a.childContextTypes;return null!==a&&void 0!==a}function th(a,b,c){if(J.current!==cb)throw Error(m(168));
y(J,b);y(S,c)}function uh(a,b,c){var d=a.stateNode;b=b.childContextTypes;if("function"!==typeof d.getChildContext)return c;d=d.getChildContext();for(var e in d)if(!(e in b))throw Error(m(108,gj(a)||"Unknown",e));return E({},c,d)}function ld(a){a=(a=a.stateNode)&&a.__reactInternalMemoizedMergedChildContext||cb;pb=J.current;y(J,a);y(S,S.current);return!0}function vh(a,b,c){var d=a.stateNode;if(!d)throw Error(m(169));c?(a=uh(a,b,pb),d.__reactInternalMemoizedMergedChildContext=a,v(S),v(J),y(J,a)):v(S);
y(S,c)}function wh(a){null===La?La=[a]:La.push(a)}function jk(a){md=!0;wh(a)}function db(){if(!Te&&null!==La){Te=!0;var a=0,b=z;try{var c=La;for(z=1;a<c.length;a++){var d=c[a];do d=d(!0);while(null!==d)}La=null;md=!1}catch(e){throw null!==La&&(La=La.slice(a+1)),xh(De,db),e;}finally{z=b,Te=!1}}return null}function qb(a,b){Ob[Pb++]=nd;Ob[Pb++]=od;od=a;nd=b}function yh(a,b,c){na[oa++]=Ma;na[oa++]=Na;na[oa++]=rb;rb=a;var d=Ma;a=Na;var e=32-ta(d)-1;d&=~(1<<e);c+=1;var f=32-ta(b)+e;if(30<f){var g=e-e%5;
f=(d&(1<<g)-1).toString(32);d>>=g;e-=g;Ma=1<<32-ta(b)+e|c<<e|d;Na=f+a}else Ma=1<<f|c<<e|d,Na=a}function Ue(a){null!==a.return&&(qb(a,1),yh(a,1,0))}function Ve(a){for(;a===od;)od=Ob[--Pb],Ob[Pb]=null,nd=Ob[--Pb],Ob[Pb]=null;for(;a===rb;)rb=na[--oa],na[oa]=null,Na=na[--oa],na[oa]=null,Ma=na[--oa],na[oa]=null}function zh(a,b){var c=pa(5,null,null,0);c.elementType="DELETED";c.stateNode=b;c.return=a;b=a.deletions;null===b?(a.deletions=[c],a.flags|=16):b.push(c)}function Ah(a,b){switch(a.tag){case 5:var c=
a.type;b=1!==b.nodeType||c.toLowerCase()!==b.nodeName.toLowerCase()?null:b;return null!==b?(a.stateNode=b,la=a,fa=Ka(b.firstChild),!0):!1;case 6:return b=""===a.pendingProps||3!==b.nodeType?null:b,null!==b?(a.stateNode=b,la=a,fa=null,!0):!1;case 13:return b=8!==b.nodeType?null:b,null!==b?(c=null!==rb?{id:Ma,overflow:Na}:null,a.memoizedState={dehydrated:b,treeContext:c,retryLane:1073741824},c=pa(18,null,null,0),c.stateNode=b,c.return=a,a.child=c,la=a,fa=null,!0):!1;default:return!1}}function We(a){return 0!==
(a.mode&1)&&0===(a.flags&128)}function Xe(a){if(D){var b=fa;if(b){var c=b;if(!Ah(a,b)){if(We(a))throw Error(m(418));b=Ka(c.nextSibling);var d=la;b&&Ah(a,b)?zh(d,c):(a.flags=a.flags&-4097|2,D=!1,la=a)}}else{if(We(a))throw Error(m(418));a.flags=a.flags&-4097|2;D=!1;la=a}}}function Bh(a){for(a=a.return;null!==a&&5!==a.tag&&3!==a.tag&&13!==a.tag;)a=a.return;la=a}function pd(a){if(a!==la)return!1;if(!D)return Bh(a),D=!0,!1;var b;(b=3!==a.tag)&&!(b=5!==a.tag)&&(b=a.type,b="head"!==b&&"body"!==b&&!Qe(a.type,
a.memoizedProps));if(b&&(b=fa)){if(We(a)){for(a=fa;a;)a=Ka(a.nextSibling);throw Error(m(418));}for(;b;)zh(a,b),b=Ka(b.nextSibling)}Bh(a);if(13===a.tag){a=a.memoizedState;a=null!==a?a.dehydrated:null;if(!a)throw Error(m(317));a:{a=a.nextSibling;for(b=0;a;){if(8===a.nodeType){var c=a.data;if("/$"===c){if(0===b){fa=Ka(a.nextSibling);break a}b--}else"$"!==c&&"$!"!==c&&"$?"!==c||b++}a=a.nextSibling}fa=null}}else fa=la?Ka(a.stateNode.nextSibling):null;return!0}function Qb(){fa=la=null;D=!1}function Ye(a){null===
wa?wa=[a]:wa.push(a)}function vc(a,b,c){a=c.ref;if(null!==a&&"function"!==typeof a&&"object"!==typeof a){if(c._owner){c=c._owner;if(c){if(1!==c.tag)throw Error(m(309));var d=c.stateNode}if(!d)throw Error(m(147,a));var e=d,f=""+a;if(null!==b&&null!==b.ref&&"function"===typeof b.ref&&b.ref._stringRef===f)return b.ref;b=function(a){var b=e.refs;null===a?delete b[f]:b[f]=a};b._stringRef=f;return b}if("string"!==typeof a)throw Error(m(284));if(!c._owner)throw Error(m(290,a));}return a}function qd(a,b){a=
Object.prototype.toString.call(b);throw Error(m(31,"[object Object]"===a?"object with keys {"+Object.keys(b).join(", ")+"}":a));}function Ch(a){var b=a._init;return b(a._payload)}function Dh(a){function b(b,c){if(a){var d=b.deletions;null===d?(b.deletions=[c],b.flags|=16):d.push(c)}}function c(c,d){if(!a)return null;for(;null!==d;)b(c,d),d=d.sibling;return null}function d(a,b){for(a=new Map;null!==b;)null!==b.key?a.set(b.key,b):a.set(b.index,b),b=b.sibling;return a}function e(a,b){a=eb(a,b);a.index=
0;a.sibling=null;return a}function f(b,c,d){b.index=d;if(!a)return b.flags|=1048576,c;d=b.alternate;if(null!==d)return d=d.index,d<c?(b.flags|=2,c):d;b.flags|=2;return c}function g(b){a&&null===b.alternate&&(b.flags|=2);return b}function h(a,b,c,d){if(null===b||6!==b.tag)return b=Ze(c,a.mode,d),b.return=a,b;b=e(b,c);b.return=a;return b}function k(a,b,c,d){var f=c.type;if(f===Bb)return l(a,b,c.props.children,d,c.key);if(null!==b&&(b.elementType===f||"object"===typeof f&&null!==f&&f.$$typeof===Ta&&
Ch(f)===b.type))return d=e(b,c.props),d.ref=vc(a,b,c),d.return=a,d;d=rd(c.type,c.key,c.props,null,a.mode,d);d.ref=vc(a,b,c);d.return=a;return d}function n(a,b,c,d){if(null===b||4!==b.tag||b.stateNode.containerInfo!==c.containerInfo||b.stateNode.implementation!==c.implementation)return b=$e(c,a.mode,d),b.return=a,b;b=e(b,c.children||[]);b.return=a;return b}function l(a,b,c,d,f){if(null===b||7!==b.tag)return b=sb(c,a.mode,d,f),b.return=a,b;b=e(b,c);b.return=a;return b}function u(a,b,c){if("string"===
typeof b&&""!==b||"number"===typeof b)return b=Ze(""+b,a.mode,c),b.return=a,b;if("object"===typeof b&&null!==b){switch(b.$$typeof){case sd:return c=rd(b.type,b.key,b.props,null,a.mode,c),c.ref=vc(a,null,b),c.return=a,c;case Cb:return b=$e(b,a.mode,c),b.return=a,b;case Ta:var d=b._init;return u(a,d(b._payload),c)}if(cc(b)||ac(b))return b=sb(b,a.mode,c,null),b.return=a,b;qd(a,b)}return null}function r(a,b,c,d){var e=null!==b?b.key:null;if("string"===typeof c&&""!==c||"number"===typeof c)return null!==
e?null:h(a,b,""+c,d);if("object"===typeof c&&null!==c){switch(c.$$typeof){case sd:return c.key===e?k(a,b,c,d):null;case Cb:return c.key===e?n(a,b,c,d):null;case Ta:return e=c._init,r(a,b,e(c._payload),d)}if(cc(c)||ac(c))return null!==e?null:l(a,b,c,d,null);qd(a,c)}return null}function p(a,b,c,d,e){if("string"===typeof d&&""!==d||"number"===typeof d)return a=a.get(c)||null,h(b,a,""+d,e);if("object"===typeof d&&null!==d){switch(d.$$typeof){case sd:return a=a.get(null===d.key?c:d.key)||null,k(b,a,d,
e);case Cb:return a=a.get(null===d.key?c:d.key)||null,n(b,a,d,e);case Ta:var f=d._init;return p(a,b,c,f(d._payload),e)}if(cc(d)||ac(d))return a=a.get(c)||null,l(b,a,d,e,null);qd(b,d)}return null}function x(e,g,h,k){for(var n=null,m=null,l=g,t=g=0,q=null;null!==l&&t<h.length;t++){l.index>t?(q=l,l=null):q=l.sibling;var A=r(e,l,h[t],k);if(null===A){null===l&&(l=q);break}a&&l&&null===A.alternate&&b(e,l);g=f(A,g,t);null===m?n=A:m.sibling=A;m=A;l=q}if(t===h.length)return c(e,l),D&&qb(e,t),n;if(null===l){for(;t<
h.length;t++)l=u(e,h[t],k),null!==l&&(g=f(l,g,t),null===m?n=l:m.sibling=l,m=l);D&&qb(e,t);return n}for(l=d(e,l);t<h.length;t++)q=p(l,e,t,h[t],k),null!==q&&(a&&null!==q.alternate&&l.delete(null===q.key?t:q.key),g=f(q,g,t),null===m?n=q:m.sibling=q,m=q);a&&l.forEach(function(a){return b(e,a)});D&&qb(e,t);return n}function I(e,g,h,k){var n=ac(h);if("function"!==typeof n)throw Error(m(150));h=n.call(h);if(null==h)throw Error(m(151));for(var l=n=null,q=g,t=g=0,A=null,w=h.next();null!==q&&!w.done;t++,w=
h.next()){q.index>t?(A=q,q=null):A=q.sibling;var x=r(e,q,w.value,k);if(null===x){null===q&&(q=A);break}a&&q&&null===x.alternate&&b(e,q);g=f(x,g,t);null===l?n=x:l.sibling=x;l=x;q=A}if(w.done)return c(e,q),D&&qb(e,t),n;if(null===q){for(;!w.done;t++,w=h.next())w=u(e,w.value,k),null!==w&&(g=f(w,g,t),null===l?n=w:l.sibling=w,l=w);D&&qb(e,t);return n}for(q=d(e,q);!w.done;t++,w=h.next())w=p(q,e,t,w.value,k),null!==w&&(a&&null!==w.alternate&&q.delete(null===w.key?t:w.key),g=f(w,g,t),null===l?n=w:l.sibling=
w,l=w);a&&q.forEach(function(a){return b(e,a)});D&&qb(e,t);return n}function v(a,d,f,h){"object"===typeof f&&null!==f&&f.type===Bb&&null===f.key&&(f=f.props.children);if("object"===typeof f&&null!==f){switch(f.$$typeof){case sd:a:{for(var k=f.key,n=d;null!==n;){if(n.key===k){k=f.type;if(k===Bb){if(7===n.tag){c(a,n.sibling);d=e(n,f.props.children);d.return=a;a=d;break a}}else if(n.elementType===k||"object"===typeof k&&null!==k&&k.$$typeof===Ta&&Ch(k)===n.type){c(a,n.sibling);d=e(n,f.props);d.ref=vc(a,
n,f);d.return=a;a=d;break a}c(a,n);break}else b(a,n);n=n.sibling}f.type===Bb?(d=sb(f.props.children,a.mode,h,f.key),d.return=a,a=d):(h=rd(f.type,f.key,f.props,null,a.mode,h),h.ref=vc(a,d,f),h.return=a,a=h)}return g(a);case Cb:a:{for(n=f.key;null!==d;){if(d.key===n)if(4===d.tag&&d.stateNode.containerInfo===f.containerInfo&&d.stateNode.implementation===f.implementation){c(a,d.sibling);d=e(d,f.children||[]);d.return=a;a=d;break a}else{c(a,d);break}else b(a,d);d=d.sibling}d=$e(f,a.mode,h);d.return=a;
a=d}return g(a);case Ta:return n=f._init,v(a,d,n(f._payload),h)}if(cc(f))return x(a,d,f,h);if(ac(f))return I(a,d,f,h);qd(a,f)}return"string"===typeof f&&""!==f||"number"===typeof f?(f=""+f,null!==d&&6===d.tag?(c(a,d.sibling),d=e(d,f),d.return=a,a=d):(c(a,d),d=Ze(f,a.mode,h),d.return=a,a=d),g(a)):c(a,d)}return v}function af(){bf=Rb=td=null}function cf(a,b){b=ud.current;v(ud);a._currentValue=b}function df(a,b,c){for(;null!==a;){var d=a.alternate;(a.childLanes&b)!==b?(a.childLanes|=b,null!==d&&(d.childLanes|=
b)):null!==d&&(d.childLanes&b)!==b&&(d.childLanes|=b);if(a===c)break;a=a.return}}function Sb(a,b){td=a;bf=Rb=null;a=a.dependencies;null!==a&&null!==a.firstContext&&(0!==(a.lanes&b)&&(ha=!0),a.firstContext=null)}function qa(a){var b=a._currentValue;if(bf!==a)if(a={context:a,memoizedValue:b,next:null},null===Rb){if(null===td)throw Error(m(308));Rb=a;td.dependencies={lanes:0,firstContext:a}}else Rb=Rb.next=a;return b}function ef(a){null===tb?tb=[a]:tb.push(a)}function Eh(a,b,c,d){var e=b.interleaved;
null===e?(c.next=c,ef(b)):(c.next=e.next,e.next=c);b.interleaved=c;return Oa(a,d)}function Oa(a,b){a.lanes|=b;var c=a.alternate;null!==c&&(c.lanes|=b);c=a;for(a=a.return;null!==a;)a.childLanes|=b,c=a.alternate,null!==c&&(c.childLanes|=b),c=a,a=a.return;return 3===c.tag?c.stateNode:null}function ff(a){a.updateQueue={baseState:a.memoizedState,firstBaseUpdate:null,lastBaseUpdate:null,shared:{pending:null,interleaved:null,lanes:0},effects:null}}function Fh(a,b){a=a.updateQueue;b.updateQueue===a&&(b.updateQueue=
{baseState:a.baseState,firstBaseUpdate:a.firstBaseUpdate,lastBaseUpdate:a.lastBaseUpdate,shared:a.shared,effects:a.effects})}function Pa(a,b){return{eventTime:a,lane:b,tag:0,payload:null,callback:null,next:null}}function fb(a,b,c){var d=a.updateQueue;if(null===d)return null;d=d.shared;if(0!==(p&2)){var e=d.pending;null===e?b.next=b:(b.next=e.next,e.next=b);d.pending=b;return kk(a,c)}e=d.interleaved;null===e?(b.next=b,ef(d)):(b.next=e.next,e.next=b);d.interleaved=b;return Oa(a,c)}function vd(a,b,c){b=
b.updateQueue;if(null!==b&&(b=b.shared,0!==(c&4194240))){var d=b.lanes;d&=a.pendingLanes;c|=d;b.lanes=c;xe(a,c)}}function Gh(a,b){var c=a.updateQueue,d=a.alternate;if(null!==d&&(d=d.updateQueue,c===d)){var e=null,f=null;c=c.firstBaseUpdate;if(null!==c){do{var g={eventTime:c.eventTime,lane:c.lane,tag:c.tag,payload:c.payload,callback:c.callback,next:null};null===f?e=f=g:f=f.next=g;c=c.next}while(null!==c);null===f?e=f=b:f=f.next=b}else e=f=b;c={baseState:d.baseState,firstBaseUpdate:e,lastBaseUpdate:f,
shared:d.shared,effects:d.effects};a.updateQueue=c;return}a=c.lastBaseUpdate;null===a?c.firstBaseUpdate=b:a.next=b;c.lastBaseUpdate=b}function wd(a,b,c,d){var e=a.updateQueue;gb=!1;var f=e.firstBaseUpdate,g=e.lastBaseUpdate,h=e.shared.pending;if(null!==h){e.shared.pending=null;var k=h,n=k.next;k.next=null;null===g?f=n:g.next=n;g=k;var l=a.alternate;null!==l&&(l=l.updateQueue,h=l.lastBaseUpdate,h!==g&&(null===h?l.firstBaseUpdate=n:h.next=n,l.lastBaseUpdate=k))}if(null!==f){var m=e.baseState;g=0;l=
n=k=null;h=f;do{var r=h.lane,p=h.eventTime;if((d&r)===r){null!==l&&(l=l.next={eventTime:p,lane:0,tag:h.tag,payload:h.payload,callback:h.callback,next:null});a:{var x=a,v=h;r=b;p=c;switch(v.tag){case 1:x=v.payload;if("function"===typeof x){m=x.call(p,m,r);break a}m=x;break a;case 3:x.flags=x.flags&-65537|128;case 0:x=v.payload;r="function"===typeof x?x.call(p,m,r):x;if(null===r||void 0===r)break a;m=E({},m,r);break a;case 2:gb=!0}}null!==h.callback&&0!==h.lane&&(a.flags|=64,r=e.effects,null===r?e.effects=
[h]:r.push(h))}else p={eventTime:p,lane:r,tag:h.tag,payload:h.payload,callback:h.callback,next:null},null===l?(n=l=p,k=m):l=l.next=p,g|=r;h=h.next;if(null===h)if(h=e.shared.pending,null===h)break;else r=h,h=r.next,r.next=null,e.lastBaseUpdate=r,e.shared.pending=null}while(1);null===l&&(k=m);e.baseState=k;e.firstBaseUpdate=n;e.lastBaseUpdate=l;b=e.shared.interleaved;if(null!==b){e=b;do g|=e.lane,e=e.next;while(e!==b)}else null===f&&(e.shared.lanes=0);ra|=g;a.lanes=g;a.memoizedState=m}}function Hh(a,
b,c){a=b.effects;b.effects=null;if(null!==a)for(b=0;b<a.length;b++){var d=a[b],e=d.callback;if(null!==e){d.callback=null;d=c;if("function"!==typeof e)throw Error(m(191,e));e.call(d)}}}function ub(a){if(a===wc)throw Error(m(174));return a}function gf(a,b){y(xc,b);y(yc,a);y(Ea,wc);a=b.nodeType;switch(a){case 9:case 11:b=(b=b.documentElement)?b.namespaceURI:oe(null,"");break;default:a=8===a?b.parentNode:b,b=a.namespaceURI||null,a=a.tagName,b=oe(b,a)}v(Ea);y(Ea,b)}function Tb(a){v(Ea);v(yc);v(xc)}function Ih(a){ub(xc.current);
var b=ub(Ea.current);var c=oe(b,a.type);b!==c&&(y(yc,a),y(Ea,c))}function hf(a){yc.current===a&&(v(Ea),v(yc))}function xd(a){for(var b=a;null!==b;){if(13===b.tag){var c=b.memoizedState;if(null!==c&&(c=c.dehydrated,null===c||"$?"===c.data||"$!"===c.data))return b}else if(19===b.tag&&void 0!==b.memoizedProps.revealOrder){if(0!==(b.flags&128))return b}else if(null!==b.child){b.child.return=b;b=b.child;continue}if(b===a)break;for(;null===b.sibling;){if(null===b.return||b.return===a)return null;b=b.return}b.sibling.return=
b.return;b=b.sibling}return null}function jf(){for(var a=0;a<kf.length;a++)kf[a]._workInProgressVersionPrimary=null;kf.length=0}function V(){throw Error(m(321));}function lf(a,b){if(null===b)return!1;for(var c=0;c<b.length&&c<a.length;c++)if(!ua(a[c],b[c]))return!1;return!0}function mf(a,b,c,d,e,f){vb=f;C=b;b.memoizedState=null;b.updateQueue=null;b.lanes=0;yd.current=null===a||null===a.memoizedState?lk:mk;a=c(d,e);if(zc){f=0;do{zc=!1;Ac=0;if(25<=f)throw Error(m(301));f+=1;N=K=null;b.updateQueue=null;
yd.current=nk;a=c(d,e)}while(zc)}yd.current=zd;b=null!==K&&null!==K.next;vb=0;N=K=C=null;Ad=!1;if(b)throw Error(m(300));return a}function nf(){var a=0!==Ac;Ac=0;return a}function Fa(){var a={memoizedState:null,baseState:null,baseQueue:null,queue:null,next:null};null===N?C.memoizedState=N=a:N=N.next=a;return N}function sa(){if(null===K){var a=C.alternate;a=null!==a?a.memoizedState:null}else a=K.next;var b=null===N?C.memoizedState:N.next;if(null!==b)N=b,K=a;else{if(null===a)throw Error(m(310));K=a;
a={memoizedState:K.memoizedState,baseState:K.baseState,baseQueue:K.baseQueue,queue:K.queue,next:null};null===N?C.memoizedState=N=a:N=N.next=a}return N}function Bc(a,b){return"function"===typeof b?b(a):b}function of(a,b,c){b=sa();c=b.queue;if(null===c)throw Error(m(311));c.lastRenderedReducer=a;var d=K,e=d.baseQueue,f=c.pending;if(null!==f){if(null!==e){var g=e.next;e.next=f.next;f.next=g}d.baseQueue=e=f;c.pending=null}if(null!==e){f=e.next;d=d.baseState;var h=g=null,k=null,n=f;do{var l=n.lane;if((vb&
l)===l)null!==k&&(k=k.next={lane:0,action:n.action,hasEagerState:n.hasEagerState,eagerState:n.eagerState,next:null}),d=n.hasEagerState?n.eagerState:a(d,n.action);else{var u={lane:l,action:n.action,hasEagerState:n.hasEagerState,eagerState:n.eagerState,next:null};null===k?(h=k=u,g=d):k=k.next=u;C.lanes|=l;ra|=l}n=n.next}while(null!==n&&n!==f);null===k?g=d:k.next=h;ua(d,b.memoizedState)||(ha=!0);b.memoizedState=d;b.baseState=g;b.baseQueue=k;c.lastRenderedState=d}a=c.interleaved;if(null!==a){e=a;do f=
e.lane,C.lanes|=f,ra|=f,e=e.next;while(e!==a)}else null===e&&(c.lanes=0);return[b.memoizedState,c.dispatch]}function pf(a,b,c){b=sa();c=b.queue;if(null===c)throw Error(m(311));c.lastRenderedReducer=a;var d=c.dispatch,e=c.pending,f=b.memoizedState;if(null!==e){c.pending=null;var g=e=e.next;do f=a(f,g.action),g=g.next;while(g!==e);ua(f,b.memoizedState)||(ha=!0);b.memoizedState=f;null===b.baseQueue&&(b.baseState=f);c.lastRenderedState=f}return[f,d]}function Jh(a,b,c){}function Kh(a,b,c){c=C;var d=sa(),
e=b(),f=!ua(d.memoizedState,e);f&&(d.memoizedState=e,ha=!0);d=d.queue;qf(Lh.bind(null,c,d,a),[a]);if(d.getSnapshot!==b||f||null!==N&&N.memoizedState.tag&1){c.flags|=2048;Cc(9,Mh.bind(null,c,d,e,b),void 0,null);if(null===O)throw Error(m(349));0!==(vb&30)||Nh(c,b,e)}return e}function Nh(a,b,c){a.flags|=16384;a={getSnapshot:b,value:c};b=C.updateQueue;null===b?(b={lastEffect:null,stores:null},C.updateQueue=b,b.stores=[a]):(c=b.stores,null===c?b.stores=[a]:c.push(a))}function Mh(a,b,c,d){b.value=c;b.getSnapshot=
d;Oh(b)&&Ph(a)}function Lh(a,b,c){return c(function(){Oh(b)&&Ph(a)})}function Oh(a){var b=a.getSnapshot;a=a.value;try{var c=b();return!ua(a,c)}catch(d){return!0}}function Ph(a){var b=Oa(a,1);null!==b&&xa(b,a,1,-1)}function Qh(a){var b=Fa();"function"===typeof a&&(a=a());b.memoizedState=b.baseState=a;a={pending:null,interleaved:null,lanes:0,dispatch:null,lastRenderedReducer:Bc,lastRenderedState:a};b.queue=a;a=a.dispatch=ok.bind(null,C,a);return[b.memoizedState,a]}function Cc(a,b,c,d){a={tag:a,create:b,
destroy:c,deps:d,next:null};b=C.updateQueue;null===b?(b={lastEffect:null,stores:null},C.updateQueue=b,b.lastEffect=a.next=a):(c=b.lastEffect,null===c?b.lastEffect=a.next=a:(d=c.next,c.next=a,a.next=d,b.lastEffect=a));return a}function Rh(a){return sa().memoizedState}function Bd(a,b,c,d){var e=Fa();C.flags|=a;e.memoizedState=Cc(1|b,c,void 0,void 0===d?null:d)}function Cd(a,b,c,d){var e=sa();d=void 0===d?null:d;var f=void 0;if(null!==K){var g=K.memoizedState;f=g.destroy;if(null!==d&&lf(d,g.deps)){e.memoizedState=
Cc(b,c,f,d);return}}C.flags|=a;e.memoizedState=Cc(1|b,c,f,d)}function Sh(a,b){return Bd(8390656,8,a,b)}function qf(a,b){return Cd(2048,8,a,b)}function Th(a,b){return Cd(4,2,a,b)}function Uh(a,b){return Cd(4,4,a,b)}function Vh(a,b){if("function"===typeof b)return a=a(),b(a),function(){b(null)};if(null!==b&&void 0!==b)return a=a(),b.current=a,function(){b.current=null}}function Wh(a,b,c){c=null!==c&&void 0!==c?c.concat([a]):null;return Cd(4,4,Vh.bind(null,b,a),c)}function rf(a,b){}function Xh(a,b){var c=
sa();b=void 0===b?null:b;var d=c.memoizedState;if(null!==d&&null!==b&&lf(b,d[1]))return d[0];c.memoizedState=[a,b];return a}function Yh(a,b){var c=sa();b=void 0===b?null:b;var d=c.memoizedState;if(null!==d&&null!==b&&lf(b,d[1]))return d[0];a=a();c.memoizedState=[a,b];return a}function Zh(a,b,c){if(0===(vb&21))return a.baseState&&(a.baseState=!1,ha=!0),a.memoizedState=c;ua(c,b)||(c=Dg(),C.lanes|=c,ra|=c,a.baseState=!0);return b}function pk(a,b,c){c=z;z=0!==c&&4>c?c:4;a(!0);var d=sf.transition;sf.transition=
{};try{a(!1),b()}finally{z=c,sf.transition=d}}function $h(){return sa().memoizedState}function qk(a,b,c){var d=hb(a);c={lane:d,action:c,hasEagerState:!1,eagerState:null,next:null};if(ai(a))bi(b,c);else if(c=Eh(a,b,c,d),null!==c){var e=Z();xa(c,a,d,e);ci(c,b,d)}}function ok(a,b,c){var d=hb(a),e={lane:d,action:c,hasEagerState:!1,eagerState:null,next:null};if(ai(a))bi(b,e);else{var f=a.alternate;if(0===a.lanes&&(null===f||0===f.lanes)&&(f=b.lastRenderedReducer,null!==f))try{var g=b.lastRenderedState,
h=f(g,c);e.hasEagerState=!0;e.eagerState=h;if(ua(h,g)){var k=b.interleaved;null===k?(e.next=e,ef(b)):(e.next=k.next,k.next=e);b.interleaved=e;return}}catch(n){}finally{}c=Eh(a,b,e,d);null!==c&&(e=Z(),xa(c,a,d,e),ci(c,b,d))}}function ai(a){var b=a.alternate;return a===C||null!==b&&b===C}function bi(a,b){zc=Ad=!0;var c=a.pending;null===c?b.next=b:(b.next=c.next,c.next=b);a.pending=b}function ci(a,b,c){if(0!==(c&4194240)){var d=b.lanes;d&=a.pendingLanes;c|=d;b.lanes=c;xe(a,c)}}function ya(a,b){if(a&&
a.defaultProps){b=E({},b);a=a.defaultProps;for(var c in a)void 0===b[c]&&(b[c]=a[c]);return b}return b}function tf(a,b,c,d){b=a.memoizedState;c=c(d,b);c=null===c||void 0===c?b:E({},b,c);a.memoizedState=c;0===a.lanes&&(a.updateQueue.baseState=c)}function di(a,b,c,d,e,f,g){a=a.stateNode;return"function"===typeof a.shouldComponentUpdate?a.shouldComponentUpdate(d,f,g):b.prototype&&b.prototype.isPureReactComponent?!qc(c,d)||!qc(e,f):!0}function ei(a,b,c){var d=!1,e=cb;var f=b.contextType;"object"===typeof f&&
null!==f?f=qa(f):(e=ea(b)?pb:J.current,d=b.contextTypes,f=(d=null!==d&&void 0!==d)?Nb(a,e):cb);b=new b(c,f);a.memoizedState=null!==b.state&&void 0!==b.state?b.state:null;b.updater=Dd;a.stateNode=b;b._reactInternals=a;d&&(a=a.stateNode,a.__reactInternalMemoizedUnmaskedChildContext=e,a.__reactInternalMemoizedMaskedChildContext=f);return b}function fi(a,b,c,d){a=b.state;"function"===typeof b.componentWillReceiveProps&&b.componentWillReceiveProps(c,d);"function"===typeof b.UNSAFE_componentWillReceiveProps&&
b.UNSAFE_componentWillReceiveProps(c,d);b.state!==a&&Dd.enqueueReplaceState(b,b.state,null)}function uf(a,b,c,d){var e=a.stateNode;e.props=c;e.state=a.memoizedState;e.refs={};ff(a);var f=b.contextType;"object"===typeof f&&null!==f?e.context=qa(f):(f=ea(b)?pb:J.current,e.context=Nb(a,f));e.state=a.memoizedState;f=b.getDerivedStateFromProps;"function"===typeof f&&(tf(a,b,f,c),e.state=a.memoizedState);"function"===typeof b.getDerivedStateFromProps||"function"===typeof e.getSnapshotBeforeUpdate||"function"!==
typeof e.UNSAFE_componentWillMount&&"function"!==typeof e.componentWillMount||(b=e.state,"function"===typeof e.componentWillMount&&e.componentWillMount(),"function"===typeof e.UNSAFE_componentWillMount&&e.UNSAFE_componentWillMount(),b!==e.state&&Dd.enqueueReplaceState(e,e.state,null),wd(a,c,e,d),e.state=a.memoizedState);"function"===typeof e.componentDidMount&&(a.flags|=4194308)}function Ub(a,b){try{var c="",d=b;do c+=fj(d),d=d.return;while(d);var e=c}catch(f){e="\\nError generating stack: "+f.message+
"\\n"+f.stack}return{value:a,source:b,stack:e,digest:null}}function vf(a,b,c){return{value:a,source:null,stack:null!=c?c:null,digest:null!=b?b:null}}function wf(a,b){try{console.error(b.value)}catch(c){setTimeout(function(){throw c;})}}function gi(a,b,c){c=Pa(-1,c);c.tag=3;c.payload={element:null};var d=b.value;c.callback=function(){Ed||(Ed=!0,xf=d);wf(a,b)};return c}function hi(a,b,c){c=Pa(-1,c);c.tag=3;var d=a.type.getDerivedStateFromError;if("function"===typeof d){var e=b.value;c.payload=function(){return d(e)};
c.callback=function(){wf(a,b)}}var f=a.stateNode;null!==f&&"function"===typeof f.componentDidCatch&&(c.callback=function(){wf(a,b);"function"!==typeof d&&(null===ib?ib=new Set([this]):ib.add(this));var c=b.stack;this.componentDidCatch(b.value,{componentStack:null!==c?c:""})});return c}function ii(a,b,c){var d=a.pingCache;if(null===d){d=a.pingCache=new rk;var e=new Set;d.set(b,e)}else e=d.get(b),void 0===e&&(e=new Set,d.set(b,e));e.has(c)||(e.add(c),a=sk.bind(null,a,b,c),b.then(a,a))}function ji(a){do{var b;
if(b=13===a.tag)b=a.memoizedState,b=null!==b?null!==b.dehydrated?!0:!1:!0;if(b)return a;a=a.return}while(null!==a);return null}function ki(a,b,c,d,e){if(0===(a.mode&1))return a===b?a.flags|=65536:(a.flags|=128,c.flags|=131072,c.flags&=-52805,1===c.tag&&(null===c.alternate?c.tag=17:(b=Pa(-1,1),b.tag=2,fb(c,b,1))),c.lanes|=1),a;a.flags|=65536;a.lanes=e;return a}function aa(a,b,c,d){b.child=null===a?li(b,null,c,d):Vb(b,a.child,c,d)}function mi(a,b,c,d,e){c=c.render;var f=b.ref;Sb(b,e);d=mf(a,b,c,d,f,
e);c=nf();if(null!==a&&!ha)return b.updateQueue=a.updateQueue,b.flags&=-2053,a.lanes&=~e,Qa(a,b,e);D&&c&&Ue(b);b.flags|=1;aa(a,b,d,e);return b.child}function ni(a,b,c,d,e){if(null===a){var f=c.type;if("function"===typeof f&&!yf(f)&&void 0===f.defaultProps&&null===c.compare&&void 0===c.defaultProps)return b.tag=15,b.type=f,oi(a,b,f,d,e);a=rd(c.type,null,d,b,b.mode,e);a.ref=b.ref;a.return=b;return b.child=a}f=a.child;if(0===(a.lanes&e)){var g=f.memoizedProps;c=c.compare;c=null!==c?c:qc;if(c(g,d)&&a.ref===
b.ref)return Qa(a,b,e)}b.flags|=1;a=eb(f,d);a.ref=b.ref;a.return=b;return b.child=a}function oi(a,b,c,d,e){if(null!==a){var f=a.memoizedProps;if(qc(f,d)&&a.ref===b.ref)if(ha=!1,b.pendingProps=d=f,0!==(a.lanes&e))0!==(a.flags&131072)&&(ha=!0);else return b.lanes=a.lanes,Qa(a,b,e)}return zf(a,b,c,d,e)}function pi(a,b,c){var d=b.pendingProps,e=d.children,f=null!==a?a.memoizedState:null;if("hidden"===d.mode)if(0===(b.mode&1))b.memoizedState={baseLanes:0,cachePool:null,transitions:null},y(Ga,ba),ba|=c;
else{if(0===(c&1073741824))return a=null!==f?f.baseLanes|c:c,b.lanes=b.childLanes=1073741824,b.memoizedState={baseLanes:a,cachePool:null,transitions:null},b.updateQueue=null,y(Ga,ba),ba|=a,null;b.memoizedState={baseLanes:0,cachePool:null,transitions:null};d=null!==f?f.baseLanes:c;y(Ga,ba);ba|=d}else null!==f?(d=f.baseLanes|c,b.memoizedState=null):d=c,y(Ga,ba),ba|=d;aa(a,b,e,c);return b.child}function qi(a,b){var c=b.ref;if(null===a&&null!==c||null!==a&&a.ref!==c)b.flags|=512,b.flags|=2097152}function zf(a,
b,c,d,e){var f=ea(c)?pb:J.current;f=Nb(b,f);Sb(b,e);c=mf(a,b,c,d,f,e);d=nf();if(null!==a&&!ha)return b.updateQueue=a.updateQueue,b.flags&=-2053,a.lanes&=~e,Qa(a,b,e);D&&d&&Ue(b);b.flags|=1;aa(a,b,c,e);return b.child}function ri(a,b,c,d,e){if(ea(c)){var f=!0;ld(b)}else f=!1;Sb(b,e);if(null===b.stateNode)Fd(a,b),ei(b,c,d),uf(b,c,d,e),d=!0;else if(null===a){var g=b.stateNode,h=b.memoizedProps;g.props=h;var k=g.context,n=c.contextType;"object"===typeof n&&null!==n?n=qa(n):(n=ea(c)?pb:J.current,n=Nb(b,
n));var l=c.getDerivedStateFromProps,m="function"===typeof l||"function"===typeof g.getSnapshotBeforeUpdate;m||"function"!==typeof g.UNSAFE_componentWillReceiveProps&&"function"!==typeof g.componentWillReceiveProps||(h!==d||k!==n)&&fi(b,g,d,n);gb=!1;var r=b.memoizedState;g.state=r;wd(b,d,g,e);k=b.memoizedState;h!==d||r!==k||S.current||gb?("function"===typeof l&&(tf(b,c,l,d),k=b.memoizedState),(h=gb||di(b,c,h,d,r,k,n))?(m||"function"!==typeof g.UNSAFE_componentWillMount&&"function"!==typeof g.componentWillMount||
("function"===typeof g.componentWillMount&&g.componentWillMount(),"function"===typeof g.UNSAFE_componentWillMount&&g.UNSAFE_componentWillMount()),"function"===typeof g.componentDidMount&&(b.flags|=4194308)):("function"===typeof g.componentDidMount&&(b.flags|=4194308),b.memoizedProps=d,b.memoizedState=k),g.props=d,g.state=k,g.context=n,d=h):("function"===typeof g.componentDidMount&&(b.flags|=4194308),d=!1)}else{g=b.stateNode;Fh(a,b);h=b.memoizedProps;n=b.type===b.elementType?h:ya(b.type,h);g.props=
n;m=b.pendingProps;r=g.context;k=c.contextType;"object"===typeof k&&null!==k?k=qa(k):(k=ea(c)?pb:J.current,k=Nb(b,k));var p=c.getDerivedStateFromProps;(l="function"===typeof p||"function"===typeof g.getSnapshotBeforeUpdate)||"function"!==typeof g.UNSAFE_componentWillReceiveProps&&"function"!==typeof g.componentWillReceiveProps||(h!==m||r!==k)&&fi(b,g,d,k);gb=!1;r=b.memoizedState;g.state=r;wd(b,d,g,e);var x=b.memoizedState;h!==m||r!==x||S.current||gb?("function"===typeof p&&(tf(b,c,p,d),x=b.memoizedState),
(n=gb||di(b,c,n,d,r,x,k)||!1)?(l||"function"!==typeof g.UNSAFE_componentWillUpdate&&"function"!==typeof g.componentWillUpdate||("function"===typeof g.componentWillUpdate&&g.componentWillUpdate(d,x,k),"function"===typeof g.UNSAFE_componentWillUpdate&&g.UNSAFE_componentWillUpdate(d,x,k)),"function"===typeof g.componentDidUpdate&&(b.flags|=4),"function"===typeof g.getSnapshotBeforeUpdate&&(b.flags|=1024)):("function"!==typeof g.componentDidUpdate||h===a.memoizedProps&&r===a.memoizedState||(b.flags|=
4),"function"!==typeof g.getSnapshotBeforeUpdate||h===a.memoizedProps&&r===a.memoizedState||(b.flags|=1024),b.memoizedProps=d,b.memoizedState=x),g.props=d,g.state=x,g.context=k,d=n):("function"!==typeof g.componentDidUpdate||h===a.memoizedProps&&r===a.memoizedState||(b.flags|=4),"function"!==typeof g.getSnapshotBeforeUpdate||h===a.memoizedProps&&r===a.memoizedState||(b.flags|=1024),d=!1)}return Af(a,b,c,d,f,e)}function Af(a,b,c,d,e,f){qi(a,b);var g=0!==(b.flags&128);if(!d&&!g)return e&&vh(b,c,!1),
Qa(a,b,f);d=b.stateNode;tk.current=b;var h=g&&"function"!==typeof c.getDerivedStateFromError?null:d.render();b.flags|=1;null!==a&&g?(b.child=Vb(b,a.child,null,f),b.child=Vb(b,null,h,f)):aa(a,b,h,f);b.memoizedState=d.state;e&&vh(b,c,!0);return b.child}function si(a){var b=a.stateNode;b.pendingContext?th(a,b.pendingContext,b.pendingContext!==b.context):b.context&&th(a,b.context,!1);gf(a,b.containerInfo)}function ti(a,b,c,d,e){Qb();Ye(e);b.flags|=256;aa(a,b,c,d);return b.child}function Bf(a){return{baseLanes:a,
cachePool:null,transitions:null}}function ui(a,b,c){var d=b.pendingProps,e=F.current,f=!1,g=0!==(b.flags&128),h;(h=g)||(h=null!==a&&null===a.memoizedState?!1:0!==(e&2));if(h)f=!0,b.flags&=-129;else if(null===a||null!==a.memoizedState)e|=1;y(F,e&1);if(null===a){Xe(b);a=b.memoizedState;if(null!==a&&(a=a.dehydrated,null!==a))return 0===(b.mode&1)?b.lanes=1:"$!"===a.data?b.lanes=8:b.lanes=1073741824,null;g=d.children;a=d.fallback;return f?(d=b.mode,f=b.child,g={mode:"hidden",children:g},0===(d&1)&&null!==
f?(f.childLanes=0,f.pendingProps=g):f=Gd(g,d,0,null),a=sb(a,d,c,null),f.return=b,a.return=b,f.sibling=a,b.child=f,b.child.memoizedState=Bf(c),b.memoizedState=Cf,a):Df(b,g)}e=a.memoizedState;if(null!==e&&(h=e.dehydrated,null!==h))return uk(a,b,g,d,h,e,c);if(f){f=d.fallback;g=b.mode;e=a.child;h=e.sibling;var k={mode:"hidden",children:d.children};0===(g&1)&&b.child!==e?(d=b.child,d.childLanes=0,d.pendingProps=k,b.deletions=null):(d=eb(e,k),d.subtreeFlags=e.subtreeFlags&14680064);null!==h?f=eb(h,f):(f=
sb(f,g,c,null),f.flags|=2);f.return=b;d.return=b;d.sibling=f;b.child=d;d=f;f=b.child;g=a.child.memoizedState;g=null===g?Bf(c):{baseLanes:g.baseLanes|c,cachePool:null,transitions:g.transitions};f.memoizedState=g;f.childLanes=a.childLanes&~c;b.memoizedState=Cf;return d}f=a.child;a=f.sibling;d=eb(f,{mode:"visible",children:d.children});0===(b.mode&1)&&(d.lanes=c);d.return=b;d.sibling=null;null!==a&&(c=b.deletions,null===c?(b.deletions=[a],b.flags|=16):c.push(a));b.child=d;b.memoizedState=null;return d}
function Df(a,b,c){b=Gd({mode:"visible",children:b},a.mode,0,null);b.return=a;return a.child=b}function Hd(a,b,c,d){null!==d&&Ye(d);Vb(b,a.child,null,c);a=Df(b,b.pendingProps.children);a.flags|=2;b.memoizedState=null;return a}function uk(a,b,c,d,e,f,g){if(c){if(b.flags&256)return b.flags&=-257,d=vf(Error(m(422))),Hd(a,b,g,d);if(null!==b.memoizedState)return b.child=a.child,b.flags|=128,null;f=d.fallback;e=b.mode;d=Gd({mode:"visible",children:d.children},e,0,null);f=sb(f,e,g,null);f.flags|=2;d.return=
b;f.return=b;d.sibling=f;b.child=d;0!==(b.mode&1)&&Vb(b,a.child,null,g);b.child.memoizedState=Bf(g);b.memoizedState=Cf;return f}if(0===(b.mode&1))return Hd(a,b,g,null);if("$!"===e.data){d=e.nextSibling&&e.nextSibling.dataset;if(d)var h=d.dgst;d=h;f=Error(m(419));d=vf(f,d,void 0);return Hd(a,b,g,d)}h=0!==(g&a.childLanes);if(ha||h){d=O;if(null!==d){switch(g&-g){case 4:e=2;break;case 16:e=8;break;case 64:case 128:case 256:case 512:case 1024:case 2048:case 4096:case 8192:case 16384:case 32768:case 65536:case 131072:case 262144:case 524288:case 1048576:case 2097152:case 4194304:case 8388608:case 16777216:case 33554432:case 67108864:e=
32;break;case 536870912:e=268435456;break;default:e=0}e=0!==(e&(d.suspendedLanes|g))?0:e;0!==e&&e!==f.retryLane&&(f.retryLane=e,Oa(a,e),xa(d,a,e,-1))}Ef();d=vf(Error(m(421)));return Hd(a,b,g,d)}if("$?"===e.data)return b.flags|=128,b.child=a.child,b=vk.bind(null,a),e._reactRetry=b,null;a=f.treeContext;fa=Ka(e.nextSibling);la=b;D=!0;wa=null;null!==a&&(na[oa++]=Ma,na[oa++]=Na,na[oa++]=rb,Ma=a.id,Na=a.overflow,rb=b);b=Df(b,d.children);b.flags|=4096;return b}function vi(a,b,c){a.lanes|=b;var d=a.alternate;
null!==d&&(d.lanes|=b);df(a.return,b,c)}function Ff(a,b,c,d,e){var f=a.memoizedState;null===f?a.memoizedState={isBackwards:b,rendering:null,renderingStartTime:0,last:d,tail:c,tailMode:e}:(f.isBackwards=b,f.rendering=null,f.renderingStartTime=0,f.last=d,f.tail=c,f.tailMode=e)}function wi(a,b,c){var d=b.pendingProps,e=d.revealOrder,f=d.tail;aa(a,b,d.children,c);d=F.current;if(0!==(d&2))d=d&1|2,b.flags|=128;else{if(null!==a&&0!==(a.flags&128))a:for(a=b.child;null!==a;){if(13===a.tag)null!==a.memoizedState&&
vi(a,c,b);else if(19===a.tag)vi(a,c,b);else if(null!==a.child){a.child.return=a;a=a.child;continue}if(a===b)break a;for(;null===a.sibling;){if(null===a.return||a.return===b)break a;a=a.return}a.sibling.return=a.return;a=a.sibling}d&=1}y(F,d);if(0===(b.mode&1))b.memoizedState=null;else switch(e){case "forwards":c=b.child;for(e=null;null!==c;)a=c.alternate,null!==a&&null===xd(a)&&(e=c),c=c.sibling;c=e;null===c?(e=b.child,b.child=null):(e=c.sibling,c.sibling=null);Ff(b,!1,e,c,f);break;case "backwards":c=
null;e=b.child;for(b.child=null;null!==e;){a=e.alternate;if(null!==a&&null===xd(a)){b.child=e;break}a=e.sibling;e.sibling=c;c=e;e=a}Ff(b,!0,c,null,f);break;case "together":Ff(b,!1,null,null,void 0);break;default:b.memoizedState=null}return b.child}function Fd(a,b){0===(b.mode&1)&&null!==a&&(a.alternate=null,b.alternate=null,b.flags|=2)}function Qa(a,b,c){null!==a&&(b.dependencies=a.dependencies);ra|=b.lanes;if(0===(c&b.childLanes))return null;if(null!==a&&b.child!==a.child)throw Error(m(153));if(null!==
b.child){a=b.child;c=eb(a,a.pendingProps);b.child=c;for(c.return=b;null!==a.sibling;)a=a.sibling,c=c.sibling=eb(a,a.pendingProps),c.return=b;c.sibling=null}return b.child}function wk(a,b,c){switch(b.tag){case 3:si(b);Qb();break;case 5:Ih(b);break;case 1:ea(b.type)&&ld(b);break;case 4:gf(b,b.stateNode.containerInfo);break;case 10:var d=b.type._context,e=b.memoizedProps.value;y(ud,d._currentValue);d._currentValue=e;break;case 13:d=b.memoizedState;if(null!==d){if(null!==d.dehydrated)return y(F,F.current&
1),b.flags|=128,null;if(0!==(c&b.child.childLanes))return ui(a,b,c);y(F,F.current&1);a=Qa(a,b,c);return null!==a?a.sibling:null}y(F,F.current&1);break;case 19:d=0!==(c&b.childLanes);if(0!==(a.flags&128)){if(d)return wi(a,b,c);b.flags|=128}e=b.memoizedState;null!==e&&(e.rendering=null,e.tail=null,e.lastEffect=null);y(F,F.current);if(d)break;else return null;case 22:case 23:return b.lanes=0,pi(a,b,c)}return Qa(a,b,c)}function Dc(a,b){if(!D)switch(a.tailMode){case "hidden":b=a.tail;for(var c=null;null!==
b;)null!==b.alternate&&(c=b),b=b.sibling;null===c?a.tail=null:c.sibling=null;break;case "collapsed":c=a.tail;for(var d=null;null!==c;)null!==c.alternate&&(d=c),c=c.sibling;null===d?b||null===a.tail?a.tail=null:a.tail.sibling=null:d.sibling=null}}function W(a){var b=null!==a.alternate&&a.alternate.child===a.child,c=0,d=0;if(b)for(var e=a.child;null!==e;)c|=e.lanes|e.childLanes,d|=e.subtreeFlags&14680064,d|=e.flags&14680064,e.return=a,e=e.sibling;else for(e=a.child;null!==e;)c|=e.lanes|e.childLanes,
d|=e.subtreeFlags,d|=e.flags,e.return=a,e=e.sibling;a.subtreeFlags|=d;a.childLanes=c;return b}function xk(a,b,c){var d=b.pendingProps;Ve(b);switch(b.tag){case 2:case 16:case 15:case 0:case 11:case 7:case 8:case 12:case 9:case 14:return W(b),null;case 1:return ea(b.type)&&(v(S),v(J)),W(b),null;case 3:d=b.stateNode;Tb();v(S);v(J);jf();d.pendingContext&&(d.context=d.pendingContext,d.pendingContext=null);if(null===a||null===a.child)pd(b)?b.flags|=4:null===a||a.memoizedState.isDehydrated&&0===(b.flags&
256)||(b.flags|=1024,null!==wa&&(Gf(wa),wa=null));xi(a,b);W(b);return null;case 5:hf(b);var e=ub(xc.current);c=b.type;if(null!==a&&null!=b.stateNode)yk(a,b,c,d,e),a.ref!==b.ref&&(b.flags|=512,b.flags|=2097152);else{if(!d){if(null===b.stateNode)throw Error(m(166));W(b);return null}a=ub(Ea.current);if(pd(b)){d=b.stateNode;c=b.type;var f=b.memoizedProps;d[Da]=b;d[uc]=f;a=0!==(b.mode&1);switch(c){case "dialog":B("cancel",d);B("close",d);break;case "iframe":case "object":case "embed":B("load",d);break;
case "video":case "audio":for(e=0;e<Ec.length;e++)B(Ec[e],d);break;case "source":B("error",d);break;case "img":case "image":case "link":B("error",d);B("load",d);break;case "details":B("toggle",d);break;case "input":kg(d,f);B("invalid",d);break;case "select":d._wrapperState={wasMultiple:!!f.multiple};B("invalid",d);break;case "textarea":ng(d,f),B("invalid",d)}pe(c,f);e=null;for(var g in f)if(f.hasOwnProperty(g)){var h=f[g];"children"===g?"string"===typeof h?d.textContent!==h&&(!0!==f.suppressHydrationWarning&&
jd(d.textContent,h,a),e=["children",h]):"number"===typeof h&&d.textContent!==""+h&&(!0!==f.suppressHydrationWarning&&jd(d.textContent,h,a),e=["children",""+h]):$b.hasOwnProperty(g)&&null!=h&&"onScroll"===g&&B("scroll",d)}switch(c){case "input":Pc(d);mg(d,f,!0);break;case "textarea":Pc(d);pg(d);break;case "select":case "option":break;default:"function"===typeof f.onClick&&(d.onclick=kd)}d=e;b.updateQueue=d;null!==d&&(b.flags|=4)}else{g=9===e.nodeType?e:e.ownerDocument;"http://www.w3.org/1999/xhtml"===
a&&(a=qg(c));"http://www.w3.org/1999/xhtml"===a?"script"===c?(a=g.createElement("div"),a.innerHTML="<script>\\x3c/script>",a=a.removeChild(a.firstChild)):"string"===typeof d.is?a=g.createElement(c,{is:d.is}):(a=g.createElement(c),"select"===c&&(g=a,d.multiple?g.multiple=!0:d.size&&(g.size=d.size))):a=g.createElementNS(a,c);a[Da]=b;a[uc]=d;zk(a,b,!1,!1);b.stateNode=a;a:{g=qe(c,d);switch(c){case "dialog":B("cancel",a);B("close",a);e=d;break;case "iframe":case "object":case "embed":B("load",a);e=d;break;
case "video":case "audio":for(e=0;e<Ec.length;e++)B(Ec[e],a);e=d;break;case "source":B("error",a);e=d;break;case "img":case "image":case "link":B("error",a);B("load",a);e=d;break;case "details":B("toggle",a);e=d;break;case "input":kg(a,d);e=ke(a,d);B("invalid",a);break;case "option":e=d;break;case "select":a._wrapperState={wasMultiple:!!d.multiple};e=E({},d,{value:void 0});B("invalid",a);break;case "textarea":ng(a,d);e=ne(a,d);B("invalid",a);break;default:e=d}pe(c,e);h=e;for(f in h)if(h.hasOwnProperty(f)){var k=
h[f];"style"===f?sg(a,k):"dangerouslySetInnerHTML"===f?(k=k?k.__html:void 0,null!=k&&yi(a,k)):"children"===f?"string"===typeof k?("textarea"!==c||""!==k)&&Fc(a,k):"number"===typeof k&&Fc(a,""+k):"suppressContentEditableWarning"!==f&&"suppressHydrationWarning"!==f&&"autoFocus"!==f&&($b.hasOwnProperty(f)?null!=k&&"onScroll"===f&&B("scroll",a):null!=k&&$d(a,f,k,g))}switch(c){case "input":Pc(a);mg(a,d,!1);break;case "textarea":Pc(a);pg(a);break;case "option":null!=d.value&&a.setAttribute("value",""+Ua(d.value));
break;case "select":a.multiple=!!d.multiple;f=d.value;null!=f?Db(a,!!d.multiple,f,!1):null!=d.defaultValue&&Db(a,!!d.multiple,d.defaultValue,!0);break;default:"function"===typeof e.onClick&&(a.onclick=kd)}switch(c){case "button":case "input":case "select":case "textarea":d=!!d.autoFocus;break a;case "img":d=!0;break a;default:d=!1}}d&&(b.flags|=4)}null!==b.ref&&(b.flags|=512,b.flags|=2097152)}W(b);return null;case 6:if(a&&null!=b.stateNode)Ak(a,b,a.memoizedProps,d);else{if("string"!==typeof d&&null===
b.stateNode)throw Error(m(166));c=ub(xc.current);ub(Ea.current);if(pd(b)){d=b.stateNode;c=b.memoizedProps;d[Da]=b;if(f=d.nodeValue!==c)if(a=la,null!==a)switch(a.tag){case 3:jd(d.nodeValue,c,0!==(a.mode&1));break;case 5:!0!==a.memoizedProps.suppressHydrationWarning&&jd(d.nodeValue,c,0!==(a.mode&1))}f&&(b.flags|=4)}else d=(9===c.nodeType?c:c.ownerDocument).createTextNode(d),d[Da]=b,b.stateNode=d}W(b);return null;case 13:v(F);d=b.memoizedState;if(null===a||null!==a.memoizedState&&null!==a.memoizedState.dehydrated){if(D&&
null!==fa&&0!==(b.mode&1)&&0===(b.flags&128)){for(f=fa;f;)f=Ka(f.nextSibling);Qb();b.flags|=98560;f=!1}else if(f=pd(b),null!==d&&null!==d.dehydrated){if(null===a){if(!f)throw Error(m(318));f=b.memoizedState;f=null!==f?f.dehydrated:null;if(!f)throw Error(m(317));f[Da]=b}else Qb(),0===(b.flags&128)&&(b.memoizedState=null),b.flags|=4;W(b);f=!1}else null!==wa&&(Gf(wa),wa=null),f=!0;if(!f)return b.flags&65536?b:null}if(0!==(b.flags&128))return b.lanes=c,b;d=null!==d;d!==(null!==a&&null!==a.memoizedState)&&
d&&(b.child.flags|=8192,0!==(b.mode&1)&&(null===a||0!==(F.current&1)?0===L&&(L=3):Ef()));null!==b.updateQueue&&(b.flags|=4);W(b);return null;case 4:return Tb(),xi(a,b),null===a&&sc(b.stateNode.containerInfo),W(b),null;case 10:return cf(b.type._context),W(b),null;case 17:return ea(b.type)&&(v(S),v(J)),W(b),null;case 19:v(F);f=b.memoizedState;if(null===f)return W(b),null;d=0!==(b.flags&128);g=f.rendering;if(null===g)if(d)Dc(f,!1);else{if(0!==L||null!==a&&0!==(a.flags&128))for(a=b.child;null!==a;){g=
xd(a);if(null!==g){b.flags|=128;Dc(f,!1);d=g.updateQueue;null!==d&&(b.updateQueue=d,b.flags|=4);b.subtreeFlags=0;d=c;for(c=b.child;null!==c;)f=c,a=d,f.flags&=14680066,g=f.alternate,null===g?(f.childLanes=0,f.lanes=a,f.child=null,f.subtreeFlags=0,f.memoizedProps=null,f.memoizedState=null,f.updateQueue=null,f.dependencies=null,f.stateNode=null):(f.childLanes=g.childLanes,f.lanes=g.lanes,f.child=g.child,f.subtreeFlags=0,f.deletions=null,f.memoizedProps=g.memoizedProps,f.memoizedState=g.memoizedState,
f.updateQueue=g.updateQueue,f.type=g.type,a=g.dependencies,f.dependencies=null===a?null:{lanes:a.lanes,firstContext:a.firstContext}),c=c.sibling;y(F,F.current&1|2);return b.child}a=a.sibling}null!==f.tail&&P()>Hf&&(b.flags|=128,d=!0,Dc(f,!1),b.lanes=4194304)}else{if(!d)if(a=xd(g),null!==a){if(b.flags|=128,d=!0,c=a.updateQueue,null!==c&&(b.updateQueue=c,b.flags|=4),Dc(f,!0),null===f.tail&&"hidden"===f.tailMode&&!g.alternate&&!D)return W(b),null}else 2*P()-f.renderingStartTime>Hf&&1073741824!==c&&(b.flags|=
128,d=!0,Dc(f,!1),b.lanes=4194304);f.isBackwards?(g.sibling=b.child,b.child=g):(c=f.last,null!==c?c.sibling=g:b.child=g,f.last=g)}if(null!==f.tail)return b=f.tail,f.rendering=b,f.tail=b.sibling,f.renderingStartTime=P(),b.sibling=null,c=F.current,y(F,d?c&1|2:c&1),b;W(b);return null;case 22:case 23:return ba=Ga.current,v(Ga),d=null!==b.memoizedState,null!==a&&null!==a.memoizedState!==d&&(b.flags|=8192),d&&0!==(b.mode&1)?0!==(ba&1073741824)&&(W(b),b.subtreeFlags&6&&(b.flags|=8192)):W(b),null;case 24:return null;
case 25:return null}throw Error(m(156,b.tag));}function Bk(a,b,c){Ve(b);switch(b.tag){case 1:return ea(b.type)&&(v(S),v(J)),a=b.flags,a&65536?(b.flags=a&-65537|128,b):null;case 3:return Tb(),v(S),v(J),jf(),a=b.flags,0!==(a&65536)&&0===(a&128)?(b.flags=a&-65537|128,b):null;case 5:return hf(b),null;case 13:v(F);a=b.memoizedState;if(null!==a&&null!==a.dehydrated){if(null===b.alternate)throw Error(m(340));Qb()}a=b.flags;return a&65536?(b.flags=a&-65537|128,b):null;case 19:return v(F),null;case 4:return Tb(),
null;case 10:return cf(b.type._context),null;case 22:case 23:return ba=Ga.current,v(Ga),null;case 24:return null;default:return null}}function Wb(a,b){var c=a.ref;if(null!==c)if("function"===typeof c)try{c(null)}catch(d){G(a,b,d)}else c.current=null}function If(a,b,c){try{c()}catch(d){G(a,b,d)}}function Ck(a,b){Jf=Zc;a=ch();if(Ie(a)){if("selectionStart"in a)var c={start:a.selectionStart,end:a.selectionEnd};else a:{c=(c=a.ownerDocument)&&c.defaultView||window;var d=c.getSelection&&c.getSelection();
if(d&&0!==d.rangeCount){c=d.anchorNode;var e=d.anchorOffset,f=d.focusNode;d=d.focusOffset;try{c.nodeType,f.nodeType}catch(M){c=null;break a}var g=0,h=-1,k=-1,n=0,q=0,u=a,r=null;b:for(;;){for(var p;;){u!==c||0!==e&&3!==u.nodeType||(h=g+e);u!==f||0!==d&&3!==u.nodeType||(k=g+d);3===u.nodeType&&(g+=u.nodeValue.length);if(null===(p=u.firstChild))break;r=u;u=p}for(;;){if(u===a)break b;r===c&&++n===e&&(h=g);r===f&&++q===d&&(k=g);if(null!==(p=u.nextSibling))break;u=r;r=u.parentNode}u=p}c=-1===h||-1===k?null:
{start:h,end:k}}else c=null}c=c||{start:0,end:0}}else c=null;Kf={focusedElem:a,selectionRange:c};Zc=!1;for(l=b;null!==l;)if(b=l,a=b.child,0!==(b.subtreeFlags&1028)&&null!==a)a.return=b,l=a;else for(;null!==l;){b=l;try{var x=b.alternate;if(0!==(b.flags&1024))switch(b.tag){case 0:case 11:case 15:break;case 1:if(null!==x){var v=x.memoizedProps,z=x.memoizedState,w=b.stateNode,A=w.getSnapshotBeforeUpdate(b.elementType===b.type?v:ya(b.type,v),z);w.__reactInternalSnapshotBeforeUpdate=A}break;case 3:var t=
b.stateNode.containerInfo;1===t.nodeType?t.textContent="":9===t.nodeType&&t.documentElement&&t.removeChild(t.documentElement);break;case 5:case 6:case 4:case 17:break;default:throw Error(m(163));}}catch(M){G(b,b.return,M)}a=b.sibling;if(null!==a){a.return=b.return;l=a;break}l=b.return}x=zi;zi=!1;return x}function Gc(a,b,c){var d=b.updateQueue;d=null!==d?d.lastEffect:null;if(null!==d){var e=d=d.next;do{if((e.tag&a)===a){var f=e.destroy;e.destroy=void 0;void 0!==f&&If(b,c,f)}e=e.next}while(e!==d)}}
function Id(a,b){b=b.updateQueue;b=null!==b?b.lastEffect:null;if(null!==b){var c=b=b.next;do{if((c.tag&a)===a){var d=c.create;c.destroy=d()}c=c.next}while(c!==b)}}function Lf(a){var b=a.ref;if(null!==b){var c=a.stateNode;switch(a.tag){case 5:a=c;break;default:a=c}"function"===typeof b?b(a):b.current=a}}function Ai(a){var b=a.alternate;null!==b&&(a.alternate=null,Ai(b));a.child=null;a.deletions=null;a.sibling=null;5===a.tag&&(b=a.stateNode,null!==b&&(delete b[Da],delete b[uc],delete b[Me],delete b[Dk],
delete b[Ek]));a.stateNode=null;a.return=null;a.dependencies=null;a.memoizedProps=null;a.memoizedState=null;a.pendingProps=null;a.stateNode=null;a.updateQueue=null}function Bi(a){return 5===a.tag||3===a.tag||4===a.tag}function Ci(a){a:for(;;){for(;null===a.sibling;){if(null===a.return||Bi(a.return))return null;a=a.return}a.sibling.return=a.return;for(a=a.sibling;5!==a.tag&&6!==a.tag&&18!==a.tag;){if(a.flags&2)continue a;if(null===a.child||4===a.tag)continue a;else a.child.return=a,a=a.child}if(!(a.flags&
2))return a.stateNode}}function Mf(a,b,c){var d=a.tag;if(5===d||6===d)a=a.stateNode,b?8===c.nodeType?c.parentNode.insertBefore(a,b):c.insertBefore(a,b):(8===c.nodeType?(b=c.parentNode,b.insertBefore(a,c)):(b=c,b.appendChild(a)),c=c._reactRootContainer,null!==c&&void 0!==c||null!==b.onclick||(b.onclick=kd));else if(4!==d&&(a=a.child,null!==a))for(Mf(a,b,c),a=a.sibling;null!==a;)Mf(a,b,c),a=a.sibling}function Nf(a,b,c){var d=a.tag;if(5===d||6===d)a=a.stateNode,b?c.insertBefore(a,b):c.appendChild(a);
else if(4!==d&&(a=a.child,null!==a))for(Nf(a,b,c),a=a.sibling;null!==a;)Nf(a,b,c),a=a.sibling}function jb(a,b,c){for(c=c.child;null!==c;)Di(a,b,c),c=c.sibling}function Di(a,b,c){if(Ca&&"function"===typeof Ca.onCommitFiberUnmount)try{Ca.onCommitFiberUnmount(Uc,c)}catch(h){}switch(c.tag){case 5:X||Wb(c,b);case 6:var d=T,e=za;T=null;jb(a,b,c);T=d;za=e;null!==T&&(za?(a=T,c=c.stateNode,8===a.nodeType?a.parentNode.removeChild(c):a.removeChild(c)):T.removeChild(c.stateNode));break;case 18:null!==T&&(za?
(a=T,c=c.stateNode,8===a.nodeType?Re(a.parentNode,c):1===a.nodeType&&Re(a,c),nc(a)):Re(T,c.stateNode));break;case 4:d=T;e=za;T=c.stateNode.containerInfo;za=!0;jb(a,b,c);T=d;za=e;break;case 0:case 11:case 14:case 15:if(!X&&(d=c.updateQueue,null!==d&&(d=d.lastEffect,null!==d))){e=d=d.next;do{var f=e,g=f.destroy;f=f.tag;void 0!==g&&(0!==(f&2)?If(c,b,g):0!==(f&4)&&If(c,b,g));e=e.next}while(e!==d)}jb(a,b,c);break;case 1:if(!X&&(Wb(c,b),d=c.stateNode,"function"===typeof d.componentWillUnmount))try{d.props=
c.memoizedProps,d.state=c.memoizedState,d.componentWillUnmount()}catch(h){G(c,b,h)}jb(a,b,c);break;case 21:jb(a,b,c);break;case 22:c.mode&1?(X=(d=X)||null!==c.memoizedState,jb(a,b,c),X=d):jb(a,b,c);break;default:jb(a,b,c)}}function Ei(a){var b=a.updateQueue;if(null!==b){a.updateQueue=null;var c=a.stateNode;null===c&&(c=a.stateNode=new Fk);b.forEach(function(b){var d=Gk.bind(null,a,b);c.has(b)||(c.add(b),b.then(d,d))})}}function Aa(a,b,c){c=b.deletions;if(null!==c)for(var d=0;d<c.length;d++){var e=
c[d];try{var f=a,g=b,h=g;a:for(;null!==h;){switch(h.tag){case 5:T=h.stateNode;za=!1;break a;case 3:T=h.stateNode.containerInfo;za=!0;break a;case 4:T=h.stateNode.containerInfo;za=!0;break a}h=h.return}if(null===T)throw Error(m(160));Di(f,g,e);T=null;za=!1;var k=e.alternate;null!==k&&(k.return=null);e.return=null}catch(n){G(e,b,n)}}if(b.subtreeFlags&12854)for(b=b.child;null!==b;)Fi(b,a),b=b.sibling}function Fi(a,b,c){var d=a.alternate;c=a.flags;switch(a.tag){case 0:case 11:case 14:case 15:Aa(b,a);
Ha(a);if(c&4){try{Gc(3,a,a.return),Id(3,a)}catch(I){G(a,a.return,I)}try{Gc(5,a,a.return)}catch(I){G(a,a.return,I)}}break;case 1:Aa(b,a);Ha(a);c&512&&null!==d&&Wb(d,d.return);break;case 5:Aa(b,a);Ha(a);c&512&&null!==d&&Wb(d,d.return);if(a.flags&32){var e=a.stateNode;try{Fc(e,"")}catch(I){G(a,a.return,I)}}if(c&4&&(e=a.stateNode,null!=e)){var f=a.memoizedProps,g=null!==d?d.memoizedProps:f,h=a.type,k=a.updateQueue;a.updateQueue=null;if(null!==k)try{"input"===h&&"radio"===f.type&&null!=f.name&&lg(e,f);
qe(h,g);var n=qe(h,f);for(g=0;g<k.length;g+=2){var q=k[g],u=k[g+1];"style"===q?sg(e,u):"dangerouslySetInnerHTML"===q?yi(e,u):"children"===q?Fc(e,u):$d(e,q,u,n)}switch(h){case "input":le(e,f);break;case "textarea":og(e,f);break;case "select":var r=e._wrapperState.wasMultiple;e._wrapperState.wasMultiple=!!f.multiple;var p=f.value;null!=p?Db(e,!!f.multiple,p,!1):r!==!!f.multiple&&(null!=f.defaultValue?Db(e,!!f.multiple,f.defaultValue,!0):Db(e,!!f.multiple,f.multiple?[]:"",!1))}e[uc]=f}catch(I){G(a,a.return,
I)}}break;case 6:Aa(b,a);Ha(a);if(c&4){if(null===a.stateNode)throw Error(m(162));e=a.stateNode;f=a.memoizedProps;try{e.nodeValue=f}catch(I){G(a,a.return,I)}}break;case 3:Aa(b,a);Ha(a);if(c&4&&null!==d&&d.memoizedState.isDehydrated)try{nc(b.containerInfo)}catch(I){G(a,a.return,I)}break;case 4:Aa(b,a);Ha(a);break;case 13:Aa(b,a);Ha(a);e=a.child;e.flags&8192&&(f=null!==e.memoizedState,e.stateNode.isHidden=f,!f||null!==e.alternate&&null!==e.alternate.memoizedState||(Of=P()));c&4&&Ei(a);break;case 22:q=
null!==d&&null!==d.memoizedState;a.mode&1?(X=(n=X)||q,Aa(b,a),X=n):Aa(b,a);Ha(a);if(c&8192){n=null!==a.memoizedState;if((a.stateNode.isHidden=n)&&!q&&0!==(a.mode&1))for(l=a,q=a.child;null!==q;){for(u=l=q;null!==l;){r=l;p=r.child;switch(r.tag){case 0:case 11:case 14:case 15:Gc(4,r,r.return);break;case 1:Wb(r,r.return);var x=r.stateNode;if("function"===typeof x.componentWillUnmount){c=r;b=r.return;try{d=c,x.props=d.memoizedProps,x.state=d.memoizedState,x.componentWillUnmount()}catch(I){G(c,b,I)}}break;
case 5:Wb(r,r.return);break;case 22:if(null!==r.memoizedState){Gi(u);continue}}null!==p?(p.return=r,l=p):Gi(u)}q=q.sibling}a:for(q=null,u=a;;){if(5===u.tag){if(null===q){q=u;try{e=u.stateNode,n?(f=e.style,"function"===typeof f.setProperty?f.setProperty("display","none","important"):f.display="none"):(h=u.stateNode,k=u.memoizedProps.style,g=void 0!==k&&null!==k&&k.hasOwnProperty("display")?k.display:null,h.style.display=rg("display",g))}catch(I){G(a,a.return,I)}}}else if(6===u.tag){if(null===q)try{u.stateNode.nodeValue=
n?"":u.memoizedProps}catch(I){G(a,a.return,I)}}else if((22!==u.tag&&23!==u.tag||null===u.memoizedState||u===a)&&null!==u.child){u.child.return=u;u=u.child;continue}if(u===a)break a;for(;null===u.sibling;){if(null===u.return||u.return===a)break a;q===u&&(q=null);u=u.return}q===u&&(q=null);u.sibling.return=u.return;u=u.sibling}}break;case 19:Aa(b,a);Ha(a);c&4&&Ei(a);break;case 21:break;default:Aa(b,a),Ha(a)}}function Ha(a){var b=a.flags;if(b&2){try{a:{for(var c=a.return;null!==c;){if(Bi(c)){var d=c;
break a}c=c.return}throw Error(m(160));}switch(d.tag){case 5:var e=d.stateNode;d.flags&32&&(Fc(e,""),d.flags&=-33);var f=Ci(a);Nf(a,f,e);break;case 3:case 4:var g=d.stateNode.containerInfo,h=Ci(a);Mf(a,h,g);break;default:throw Error(m(161));}}catch(k){G(a,a.return,k)}a.flags&=-3}b&4096&&(a.flags&=-4097)}function Hk(a,b,c){l=a;Hi(a,b,c)}function Hi(a,b,c){for(var d=0!==(a.mode&1);null!==l;){var e=l,f=e.child;if(22===e.tag&&d){var g=null!==e.memoizedState||Jd;if(!g){var h=e.alternate,k=null!==h&&null!==
h.memoizedState||X;h=Jd;var n=X;Jd=g;if((X=k)&&!n)for(l=e;null!==l;)g=l,k=g.child,22===g.tag&&null!==g.memoizedState?Ii(e):null!==k?(k.return=g,l=k):Ii(e);for(;null!==f;)l=f,Hi(f,b,c),f=f.sibling;l=e;Jd=h;X=n}Ji(a,b,c)}else 0!==(e.subtreeFlags&8772)&&null!==f?(f.return=e,l=f):Ji(a,b,c)}}function Ji(a,b,c){for(;null!==l;){b=l;if(0!==(b.flags&8772)){c=b.alternate;try{if(0!==(b.flags&8772))switch(b.tag){case 0:case 11:case 15:X||Id(5,b);break;case 1:var d=b.stateNode;if(b.flags&4&&!X)if(null===c)d.componentDidMount();
else{var e=b.elementType===b.type?c.memoizedProps:ya(b.type,c.memoizedProps);d.componentDidUpdate(e,c.memoizedState,d.__reactInternalSnapshotBeforeUpdate)}var f=b.updateQueue;null!==f&&Hh(b,f,d);break;case 3:var g=b.updateQueue;if(null!==g){c=null;if(null!==b.child)switch(b.child.tag){case 5:c=b.child.stateNode;break;case 1:c=b.child.stateNode}Hh(b,g,c)}break;case 5:var h=b.stateNode;if(null===c&&b.flags&4){c=h;var k=b.memoizedProps;switch(b.type){case "button":case "input":case "select":case "textarea":k.autoFocus&&
c.focus();break;case "img":k.src&&(c.src=k.src)}}break;case 6:break;case 4:break;case 12:break;case 13:if(null===b.memoizedState){var n=b.alternate;if(null!==n){var q=n.memoizedState;if(null!==q){var p=q.dehydrated;null!==p&&nc(p)}}}break;case 19:case 17:case 21:case 22:case 23:case 25:break;default:throw Error(m(163));}X||b.flags&512&&Lf(b)}catch(r){G(b,b.return,r)}}if(b===a){l=null;break}c=b.sibling;if(null!==c){c.return=b.return;l=c;break}l=b.return}}function Gi(a){for(;null!==l;){var b=l;if(b===
a){l=null;break}var c=b.sibling;if(null!==c){c.return=b.return;l=c;break}l=b.return}}function Ii(a){for(;null!==l;){var b=l;try{switch(b.tag){case 0:case 11:case 15:var c=b.return;try{Id(4,b)}catch(k){G(b,c,k)}break;case 1:var d=b.stateNode;if("function"===typeof d.componentDidMount){var e=b.return;try{d.componentDidMount()}catch(k){G(b,e,k)}}var f=b.return;try{Lf(b)}catch(k){G(b,f,k)}break;case 5:var g=b.return;try{Lf(b)}catch(k){G(b,g,k)}}}catch(k){G(b,b.return,k)}if(b===a){l=null;break}var h=b.sibling;
if(null!==h){h.return=b.return;l=h;break}l=b.return}}function Hc(){Hf=P()+500}function Z(){return 0!==(p&6)?P():-1!==Kd?Kd:Kd=P()}function hb(a){if(0===(a.mode&1))return 1;if(0!==(p&2)&&0!==U)return U&-U;if(null!==Ik.transition)return 0===Ld&&(Ld=Dg()),Ld;a=z;if(0!==a)return a;a=window.event;a=void 0===a?16:Lg(a.type);return a}function xa(a,b,c,d){if(50<Ic)throw Ic=0,Pf=null,Error(m(185));ic(a,c,d);if(0===(p&2)||a!==O)a===O&&(0===(p&2)&&(Md|=c),4===L&&kb(a,U)),ia(a,d),1===c&&0===p&&0===(b.mode&1)&&
(Hc(),md&&db())}function ia(a,b){var c=a.callbackNode;tj(a,b);var d=Vc(a,a===O?U:0);if(0===d)null!==c&&Ki(c),a.callbackNode=null,a.callbackPriority=0;else if(b=d&-d,a.callbackPriority!==b){null!=c&&Ki(c);if(1===b)0===a.tag?jk(Li.bind(null,a)):wh(Li.bind(null,a)),Jk(function(){0===(p&6)&&db()}),c=null;else{switch(Eg(d)){case 1:c=De;break;case 4:c=Mg;break;case 16:c=ad;break;case 536870912:c=Ng;break;default:c=ad}c=Mi(c,Ni.bind(null,a))}a.callbackPriority=b;a.callbackNode=c}}function Ni(a,b){Kd=-1;
Ld=0;if(0!==(p&6))throw Error(m(327));var c=a.callbackNode;if(Xb()&&a.callbackNode!==c)return null;var d=Vc(a,a===O?U:0);if(0===d)return null;if(0!==(d&30)||0!==(d&a.expiredLanes)||b)b=Nd(a,d);else{b=d;var e=p;p|=2;var f=Oi();if(O!==a||U!==b)Ra=null,Hc(),wb(a,b);do try{Kk();break}catch(h){Pi(a,h)}while(1);af();Od.current=f;p=e;null!==H?b=0:(O=null,U=0,b=L)}if(0!==b){2===b&&(e=ve(a),0!==e&&(d=e,b=Qf(a,e)));if(1===b)throw c=Jc,wb(a,0),kb(a,d),ia(a,P()),c;if(6===b)kb(a,d);else{e=a.current.alternate;
if(0===(d&30)&&!Lk(e)&&(b=Nd(a,d),2===b&&(f=ve(a),0!==f&&(d=f,b=Qf(a,f))),1===b))throw c=Jc,wb(a,0),kb(a,d),ia(a,P()),c;a.finishedWork=e;a.finishedLanes=d;switch(b){case 0:case 1:throw Error(m(345));case 2:xb(a,ja,Ra);break;case 3:kb(a,d);if((d&130023424)===d&&(b=Of+500-P(),10<b)){if(0!==Vc(a,0))break;e=a.suspendedLanes;if((e&d)!==d){Z();a.pingedLanes|=a.suspendedLanes&e;break}a.timeoutHandle=Rf(xb.bind(null,a,ja,Ra),b);break}xb(a,ja,Ra);break;case 4:kb(a,d);if((d&4194240)===d)break;b=a.eventTimes;
for(e=-1;0<d;){var g=31-ta(d);f=1<<g;g=b[g];g>e&&(e=g);d&=~f}d=e;d=P()-d;d=(120>d?120:480>d?480:1080>d?1080:1920>d?1920:3E3>d?3E3:4320>d?4320:1960*Mk(d/1960))-d;if(10<d){a.timeoutHandle=Rf(xb.bind(null,a,ja,Ra),d);break}xb(a,ja,Ra);break;case 5:xb(a,ja,Ra);break;default:throw Error(m(329));}}}ia(a,P());return a.callbackNode===c?Ni.bind(null,a):null}function Qf(a,b){var c=Kc;a.current.memoizedState.isDehydrated&&(wb(a,b).flags|=256);a=Nd(a,b);2!==a&&(b=ja,ja=c,null!==b&&Gf(b));return a}function Gf(a){null===
ja?ja=a:ja.push.apply(ja,a)}function Lk(a){for(var b=a;;){if(b.flags&16384){var c=b.updateQueue;if(null!==c&&(c=c.stores,null!==c))for(var d=0;d<c.length;d++){var e=c[d],f=e.getSnapshot;e=e.value;try{if(!ua(f(),e))return!1}catch(g){return!1}}}c=b.child;if(b.subtreeFlags&16384&&null!==c)c.return=b,b=c;else{if(b===a)break;for(;null===b.sibling;){if(null===b.return||b.return===a)return!0;b=b.return}b.sibling.return=b.return;b=b.sibling}}return!0}function kb(a,b){b&=~Sf;b&=~Md;a.suspendedLanes|=b;a.pingedLanes&=
~b;for(a=a.expirationTimes;0<b;){var c=31-ta(b),d=1<<c;a[c]=-1;b&=~d}}function Li(a){if(0!==(p&6))throw Error(m(327));Xb();var b=Vc(a,0);if(0===(b&1))return ia(a,P()),null;var c=Nd(a,b);if(0!==a.tag&&2===c){var d=ve(a);0!==d&&(b=d,c=Qf(a,d))}if(1===c)throw c=Jc,wb(a,0),kb(a,b),ia(a,P()),c;if(6===c)throw Error(m(345));a.finishedWork=a.current.alternate;a.finishedLanes=b;xb(a,ja,Ra);ia(a,P());return null}function Tf(a,b){var c=p;p|=1;try{return a(b)}finally{p=c,0===p&&(Hc(),md&&db())}}function yb(a){null!==
lb&&0===lb.tag&&0===(p&6)&&Xb();var b=p;p|=1;var c=ca.transition,d=z;try{if(ca.transition=null,z=1,a)return a()}finally{z=d,ca.transition=c,p=b,0===(p&6)&&db()}}function wb(a,b){a.finishedWork=null;a.finishedLanes=0;var c=a.timeoutHandle;-1!==c&&(a.timeoutHandle=-1,Nk(c));if(null!==H)for(c=H.return;null!==c;){var d=c;Ve(d);switch(d.tag){case 1:d=d.type.childContextTypes;null!==d&&void 0!==d&&(v(S),v(J));break;case 3:Tb();v(S);v(J);jf();break;case 5:hf(d);break;case 4:Tb();break;case 13:v(F);break;
case 19:v(F);break;case 10:cf(d.type._context);break;case 22:case 23:ba=Ga.current,v(Ga)}c=c.return}O=a;H=a=eb(a.current,null);U=ba=b;L=0;Jc=null;Sf=Md=ra=0;ja=Kc=null;if(null!==tb){for(b=0;b<tb.length;b++)if(c=tb[b],d=c.interleaved,null!==d){c.interleaved=null;var e=d.next,f=c.pending;if(null!==f){var g=f.next;f.next=e;d.next=g}c.pending=d}tb=null}return a}function Pi(a,b){do{var c=H;try{af();yd.current=zd;if(Ad){for(var d=C.memoizedState;null!==d;){var e=d.queue;null!==e&&(e.pending=null);d=d.next}Ad=
!1}vb=0;N=K=C=null;zc=!1;Ac=0;Uf.current=null;if(null===c||null===c.return){L=1;Jc=b;H=null;break}a:{var f=a,g=c.return,h=c,k=b;b=U;h.flags|=32768;if(null!==k&&"object"===typeof k&&"function"===typeof k.then){var n=k,l=h,p=l.tag;if(0===(l.mode&1)&&(0===p||11===p||15===p)){var r=l.alternate;r?(l.updateQueue=r.updateQueue,l.memoizedState=r.memoizedState,l.lanes=r.lanes):(l.updateQueue=null,l.memoizedState=null)}var v=ji(g);if(null!==v){v.flags&=-257;ki(v,g,h,f,b);v.mode&1&&ii(f,n,b);b=v;k=n;var x=b.updateQueue;
if(null===x){var z=new Set;z.add(k);b.updateQueue=z}else x.add(k);break a}else{if(0===(b&1)){ii(f,n,b);Ef();break a}k=Error(m(426))}}else if(D&&h.mode&1){var y=ji(g);if(null!==y){0===(y.flags&65536)&&(y.flags|=256);ki(y,g,h,f,b);Ye(Ub(k,h));break a}}f=k=Ub(k,h);4!==L&&(L=2);null===Kc?Kc=[f]:Kc.push(f);f=g;do{switch(f.tag){case 3:f.flags|=65536;b&=-b;f.lanes|=b;var w=gi(f,k,b);Gh(f,w);break a;case 1:h=k;var A=f.type,t=f.stateNode;if(0===(f.flags&128)&&("function"===typeof A.getDerivedStateFromError||
null!==t&&"function"===typeof t.componentDidCatch&&(null===ib||!ib.has(t)))){f.flags|=65536;b&=-b;f.lanes|=b;var B=hi(f,h,b);Gh(f,B);break a}}f=f.return}while(null!==f)}Qi(c)}catch(ma){b=ma;H===c&&null!==c&&(H=c=c.return);continue}break}while(1)}function Oi(){var a=Od.current;Od.current=zd;return null===a?zd:a}function Ef(){if(0===L||3===L||2===L)L=4;null===O||0===(ra&268435455)&&0===(Md&268435455)||kb(O,U)}function Nd(a,b){var c=p;p|=2;var d=Oi();if(O!==a||U!==b)Ra=null,wb(a,b);do try{Ok();break}catch(e){Pi(a,
e)}while(1);af();p=c;Od.current=d;if(null!==H)throw Error(m(261));O=null;U=0;return L}function Ok(){for(;null!==H;)Ri(H)}function Kk(){for(;null!==H&&!Pk();)Ri(H)}function Ri(a){var b=Qk(a.alternate,a,ba);a.memoizedProps=a.pendingProps;null===b?Qi(a):H=b;Uf.current=null}function Qi(a){var b=a;do{var c=b.alternate;a=b.return;if(0===(b.flags&32768)){if(c=xk(c,b,ba),null!==c){H=c;return}}else{c=Bk(c,b);if(null!==c){c.flags&=32767;H=c;return}if(null!==a)a.flags|=32768,a.subtreeFlags=0,a.deletions=null;
else{L=6;H=null;return}}b=b.sibling;if(null!==b){H=b;return}H=b=a}while(null!==b);0===L&&(L=5)}function xb(a,b,c){var d=z,e=ca.transition;try{ca.transition=null,z=1,Rk(a,b,c,d)}finally{ca.transition=e,z=d}return null}function Rk(a,b,c,d){do Xb();while(null!==lb);if(0!==(p&6))throw Error(m(327));c=a.finishedWork;var e=a.finishedLanes;if(null===c)return null;a.finishedWork=null;a.finishedLanes=0;if(c===a.current)throw Error(m(177));a.callbackNode=null;a.callbackPriority=0;var f=c.lanes|c.childLanes;
uj(a,f);a===O&&(H=O=null,U=0);0===(c.subtreeFlags&2064)&&0===(c.flags&2064)||Pd||(Pd=!0,Mi(ad,function(){Xb();return null}));f=0!==(c.flags&15990);if(0!==(c.subtreeFlags&15990)||f){f=ca.transition;ca.transition=null;var g=z;z=1;var h=p;p|=4;Uf.current=null;Ck(a,c);Fi(c,a);Tj(Kf);Zc=!!Jf;Kf=Jf=null;a.current=c;Hk(c,a,e);Sk();p=h;z=g;ca.transition=f}else a.current=c;Pd&&(Pd=!1,lb=a,Qd=e);f=a.pendingLanes;0===f&&(ib=null);oj(c.stateNode,d);ia(a,P());if(null!==b)for(d=a.onRecoverableError,c=0;c<b.length;c++)e=
b[c],d(e.value,{componentStack:e.stack,digest:e.digest});if(Ed)throw Ed=!1,a=xf,xf=null,a;0!==(Qd&1)&&0!==a.tag&&Xb();f=a.pendingLanes;0!==(f&1)?a===Pf?Ic++:(Ic=0,Pf=a):Ic=0;db();return null}function Xb(){if(null!==lb){var a=Eg(Qd),b=ca.transition,c=z;try{ca.transition=null;z=16>a?16:a;if(null===lb)var d=!1;else{a=lb;lb=null;Qd=0;if(0!==(p&6))throw Error(m(331));var e=p;p|=4;for(l=a.current;null!==l;){var f=l,g=f.child;if(0!==(l.flags&16)){var h=f.deletions;if(null!==h){for(var k=0;k<h.length;k++){var n=
h[k];for(l=n;null!==l;){var q=l;switch(q.tag){case 0:case 11:case 15:Gc(8,q,f)}var u=q.child;if(null!==u)u.return=q,l=u;else for(;null!==l;){q=l;var r=q.sibling,v=q.return;Ai(q);if(q===n){l=null;break}if(null!==r){r.return=v;l=r;break}l=v}}}var x=f.alternate;if(null!==x){var y=x.child;if(null!==y){x.child=null;do{var C=y.sibling;y.sibling=null;y=C}while(null!==y)}}l=f}}if(0!==(f.subtreeFlags&2064)&&null!==g)g.return=f,l=g;else b:for(;null!==l;){f=l;if(0!==(f.flags&2048))switch(f.tag){case 0:case 11:case 15:Gc(9,
f,f.return)}var w=f.sibling;if(null!==w){w.return=f.return;l=w;break b}l=f.return}}var A=a.current;for(l=A;null!==l;){g=l;var t=g.child;if(0!==(g.subtreeFlags&2064)&&null!==t)t.return=g,l=t;else b:for(g=A;null!==l;){h=l;if(0!==(h.flags&2048))try{switch(h.tag){case 0:case 11:case 15:Id(9,h)}}catch(ma){G(h,h.return,ma)}if(h===g){l=null;break b}var B=h.sibling;if(null!==B){B.return=h.return;l=B;break b}l=h.return}}p=e;db();if(Ca&&"function"===typeof Ca.onPostCommitFiberRoot)try{Ca.onPostCommitFiberRoot(Uc,
a)}catch(ma){}d=!0}return d}finally{z=c,ca.transition=b}}return!1}function Si(a,b,c){b=Ub(c,b);b=gi(a,b,1);a=fb(a,b,1);b=Z();null!==a&&(ic(a,1,b),ia(a,b))}function G(a,b,c){if(3===a.tag)Si(a,a,c);else for(;null!==b;){if(3===b.tag){Si(b,a,c);break}else if(1===b.tag){var d=b.stateNode;if("function"===typeof b.type.getDerivedStateFromError||"function"===typeof d.componentDidCatch&&(null===ib||!ib.has(d))){a=Ub(c,a);a=hi(b,a,1);b=fb(b,a,1);a=Z();null!==b&&(ic(b,1,a),ia(b,a));break}}b=b.return}}function sk(a,
b,c){var d=a.pingCache;null!==d&&d.delete(b);b=Z();a.pingedLanes|=a.suspendedLanes&c;O===a&&(U&c)===c&&(4===L||3===L&&(U&130023424)===U&&500>P()-Of?wb(a,0):Sf|=c);ia(a,b)}function Ti(a,b){0===b&&(0===(a.mode&1)?b=1:(b=Rd,Rd<<=1,0===(Rd&130023424)&&(Rd=4194304)));var c=Z();a=Oa(a,b);null!==a&&(ic(a,b,c),ia(a,c))}function vk(a){var b=a.memoizedState,c=0;null!==b&&(c=b.retryLane);Ti(a,c)}function Gk(a,b){var c=0;switch(a.tag){case 13:var d=a.stateNode;var e=a.memoizedState;null!==e&&(c=e.retryLane);
break;case 19:d=a.stateNode;break;default:throw Error(m(314));}null!==d&&d.delete(b);Ti(a,c)}function Mi(a,b){return xh(a,b)}function Tk(a,b,c,d){this.tag=a;this.key=c;this.sibling=this.child=this.return=this.stateNode=this.type=this.elementType=null;this.index=0;this.ref=null;this.pendingProps=b;this.dependencies=this.memoizedState=this.updateQueue=this.memoizedProps=null;this.mode=d;this.subtreeFlags=this.flags=0;this.deletions=null;this.childLanes=this.lanes=0;this.alternate=null}function yf(a){a=
a.prototype;return!(!a||!a.isReactComponent)}function Uk(a){if("function"===typeof a)return yf(a)?1:0;if(void 0!==a&&null!==a){a=a.$$typeof;if(a===ie)return 11;if(a===je)return 14}return 2}function eb(a,b){var c=a.alternate;null===c?(c=pa(a.tag,b,a.key,a.mode),c.elementType=a.elementType,c.type=a.type,c.stateNode=a.stateNode,c.alternate=a,a.alternate=c):(c.pendingProps=b,c.type=a.type,c.flags=0,c.subtreeFlags=0,c.deletions=null);c.flags=a.flags&14680064;c.childLanes=a.childLanes;c.lanes=a.lanes;c.child=
a.child;c.memoizedProps=a.memoizedProps;c.memoizedState=a.memoizedState;c.updateQueue=a.updateQueue;b=a.dependencies;c.dependencies=null===b?null:{lanes:b.lanes,firstContext:b.firstContext};c.sibling=a.sibling;c.index=a.index;c.ref=a.ref;return c}function rd(a,b,c,d,e,f){var g=2;d=a;if("function"===typeof a)yf(a)&&(g=1);else if("string"===typeof a)g=5;else a:switch(a){case Bb:return sb(c.children,e,f,b);case fe:g=8;e|=8;break;case ee:return a=pa(12,c,b,e|2),a.elementType=ee,a.lanes=f,a;case ge:return a=
pa(13,c,b,e),a.elementType=ge,a.lanes=f,a;case he:return a=pa(19,c,b,e),a.elementType=he,a.lanes=f,a;case Ui:return Gd(c,e,f,b);default:if("object"===typeof a&&null!==a)switch(a.$$typeof){case hg:g=10;break a;case gg:g=9;break a;case ie:g=11;break a;case je:g=14;break a;case Ta:g=16;d=null;break a}throw Error(m(130,null==a?a:typeof a,""));}b=pa(g,c,b,e);b.elementType=a;b.type=d;b.lanes=f;return b}function sb(a,b,c,d){a=pa(7,a,d,b);a.lanes=c;return a}function Gd(a,b,c,d){a=pa(22,a,d,b);a.elementType=
Ui;a.lanes=c;a.stateNode={isHidden:!1};return a}function Ze(a,b,c){a=pa(6,a,null,b);a.lanes=c;return a}function $e(a,b,c){b=pa(4,null!==a.children?a.children:[],a.key,b);b.lanes=c;b.stateNode={containerInfo:a.containerInfo,pendingChildren:null,implementation:a.implementation};return b}function Vk(a,b,c,d,e){this.tag=b;this.containerInfo=a;this.finishedWork=this.pingCache=this.current=this.pendingChildren=null;this.timeoutHandle=-1;this.callbackNode=this.pendingContext=this.context=null;this.callbackPriority=
0;this.eventTimes=we(0);this.expirationTimes=we(-1);this.entangledLanes=this.finishedLanes=this.mutableReadLanes=this.expiredLanes=this.pingedLanes=this.suspendedLanes=this.pendingLanes=0;this.entanglements=we(0);this.identifierPrefix=d;this.onRecoverableError=e;this.mutableSourceEagerHydrationData=null}function Vf(a,b,c,d,e,f,g,h,k,l){a=new Vk(a,b,c,h,k);1===b?(b=1,!0===f&&(b|=8)):b=0;f=pa(3,null,null,b);a.current=f;f.stateNode=a;f.memoizedState={element:d,isDehydrated:c,cache:null,transitions:null,
pendingSuspenseBoundaries:null};ff(f);return a}function Wk(a,b,c){var d=3<arguments.length&&void 0!==arguments[3]?arguments[3]:null;return{$$typeof:Cb,key:null==d?null:""+d,children:a,containerInfo:b,implementation:c}}function Vi(a){if(!a)return cb;a=a._reactInternals;a:{if(nb(a)!==a||1!==a.tag)throw Error(m(170));var b=a;do{switch(b.tag){case 3:b=b.stateNode.context;break a;case 1:if(ea(b.type)){b=b.stateNode.__reactInternalMemoizedMergedChildContext;break a}}b=b.return}while(null!==b);throw Error(m(171));
}if(1===a.tag){var c=a.type;if(ea(c))return uh(a,c,b)}return b}function Wi(a,b,c,d,e,f,g,h,k,l){a=Vf(c,d,!0,a,e,f,g,h,k);a.context=Vi(null);c=a.current;d=Z();e=hb(c);f=Pa(d,e);f.callback=void 0!==b&&null!==b?b:null;fb(c,f,e);a.current.lanes=e;ic(a,e,d);ia(a,d);return a}function Sd(a,b,c,d){var e=b.current,f=Z(),g=hb(e);c=Vi(c);null===b.context?b.context=c:b.pendingContext=c;b=Pa(f,g);b.payload={element:a};d=void 0===d?null:d;null!==d&&(b.callback=d);a=fb(e,b,g);null!==a&&(xa(a,e,g,f),vd(a,e,g));return g}
function Td(a){a=a.current;if(!a.child)return null;switch(a.child.tag){case 5:return a.child.stateNode;default:return a.child.stateNode}}function Xi(a,b){a=a.memoizedState;if(null!==a&&null!==a.dehydrated){var c=a.retryLane;a.retryLane=0!==c&&c<b?c:b}}function Wf(a,b){Xi(a,b);(a=a.alternate)&&Xi(a,b)}function Xk(a){a=Bg(a);return null===a?null:a.stateNode}function Yk(a){return null}function Xf(a){this._internalRoot=a}function Ud(a){this._internalRoot=a}function Yf(a){return!(!a||1!==a.nodeType&&9!==
a.nodeType&&11!==a.nodeType)}function Vd(a){return!(!a||1!==a.nodeType&&9!==a.nodeType&&11!==a.nodeType&&(8!==a.nodeType||" react-mount-point-unstable "!==a.nodeValue))}function Yi(){}function Zk(a,b,c,d,e){if(e){if("function"===typeof d){var f=d;d=function(){var a=Td(g);f.call(a)}}var g=Wi(b,d,a,0,null,!1,!1,"",Yi);a._reactRootContainer=g;a[Ja]=g.current;sc(8===a.nodeType?a.parentNode:a);yb();return g}for(;e=a.lastChild;)a.removeChild(e);if("function"===typeof d){var h=d;d=function(){var a=Td(k);
h.call(a)}}var k=Vf(a,0,!1,null,null,!1,!1,"",Yi);a._reactRootContainer=k;a[Ja]=k.current;sc(8===a.nodeType?a.parentNode:a);yb(function(){Sd(b,k,c,d)});return k}function Wd(a,b,c,d,e){var f=c._reactRootContainer;if(f){var g=f;if("function"===typeof e){var h=e;e=function(){var a=Td(g);h.call(a)}}Sd(b,g,a,e)}else g=Zk(c,b,a,e,d);return Td(g)}var cg=new Set,$b={},Ia=!("undefined"===typeof window||"undefined"===typeof window.document||"undefined"===typeof window.document.createElement),Zd=Object.prototype.hasOwnProperty,
cj=/^[:A-Z_a-z\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD][:A-Z_a-z\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD\\-.0-9\\u00B7\\u0300-\\u036F\\u203F-\\u2040]*$/,eg={},dg={},R={};"children dangerouslySetInnerHTML defaultValue defaultChecked innerHTML suppressContentEditableWarning suppressHydrationWarning style".split(" ").forEach(function(a){R[a]=
new Y(a,0,!1,a,null,!1,!1)});[["acceptCharset","accept-charset"],["className","class"],["htmlFor","for"],["httpEquiv","http-equiv"]].forEach(function(a){var b=a[0];R[b]=new Y(b,1,!1,a[1],null,!1,!1)});["contentEditable","draggable","spellCheck","value"].forEach(function(a){R[a]=new Y(a,2,!1,a.toLowerCase(),null,!1,!1)});["autoReverse","externalResourcesRequired","focusable","preserveAlpha"].forEach(function(a){R[a]=new Y(a,2,!1,a,null,!1,!1)});"allowFullScreen async autoFocus autoPlay controls default defer disabled disablePictureInPicture disableRemotePlayback formNoValidate hidden loop noModule noValidate open playsInline readOnly required reversed scoped seamless itemScope".split(" ").forEach(function(a){R[a]=
new Y(a,3,!1,a.toLowerCase(),null,!1,!1)});["checked","multiple","muted","selected"].forEach(function(a){R[a]=new Y(a,3,!0,a,null,!1,!1)});["capture","download"].forEach(function(a){R[a]=new Y(a,4,!1,a,null,!1,!1)});["cols","rows","size","span"].forEach(function(a){R[a]=new Y(a,6,!1,a,null,!1,!1)});["rowSpan","start"].forEach(function(a){R[a]=new Y(a,5,!1,a.toLowerCase(),null,!1,!1)});var Zf=/[\\-:]([a-z])/g,$f=function(a){return a[1].toUpperCase()};"accent-height alignment-baseline arabic-form baseline-shift cap-height clip-path clip-rule color-interpolation color-interpolation-filters color-profile color-rendering dominant-baseline enable-background fill-opacity fill-rule flood-color flood-opacity font-family font-size font-size-adjust font-stretch font-style font-variant font-weight glyph-name glyph-orientation-horizontal glyph-orientation-vertical horiz-adv-x horiz-origin-x image-rendering letter-spacing lighting-color marker-end marker-mid marker-start overline-position overline-thickness paint-order panose-1 pointer-events rendering-intent shape-rendering stop-color stop-opacity strikethrough-position strikethrough-thickness stroke-dasharray stroke-dashoffset stroke-linecap stroke-linejoin stroke-miterlimit stroke-opacity stroke-width text-anchor text-decoration text-rendering underline-position underline-thickness unicode-bidi unicode-range units-per-em v-alphabetic v-hanging v-ideographic v-mathematical vector-effect vert-adv-y vert-origin-x vert-origin-y word-spacing writing-mode xmlns:xlink x-height".split(" ").forEach(function(a){var b=
a.replace(Zf,$f);R[b]=new Y(b,1,!1,a,null,!1,!1)});"xlink:actuate xlink:arcrole xlink:role xlink:show xlink:title xlink:type".split(" ").forEach(function(a){var b=a.replace(Zf,$f);R[b]=new Y(b,1,!1,a,"http://www.w3.org/1999/xlink",!1,!1)});["xml:base","xml:lang","xml:space"].forEach(function(a){var b=a.replace(Zf,$f);R[b]=new Y(b,1,!1,a,"http://www.w3.org/XML/1998/namespace",!1,!1)});["tabIndex","crossOrigin"].forEach(function(a){R[a]=new Y(a,1,!1,a.toLowerCase(),null,!1,!1)});R.xlinkHref=new Y("xlinkHref",
1,!1,"xlink:href","http://www.w3.org/1999/xlink",!0,!1);["src","href","action","formAction"].forEach(function(a){R[a]=new Y(a,1,!1,a.toLowerCase(),null,!0,!0)});var Sa=zb.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED,sd=Symbol.for("react.element"),Cb=Symbol.for("react.portal"),Bb=Symbol.for("react.fragment"),fe=Symbol.for("react.strict_mode"),ee=Symbol.for("react.profiler"),hg=Symbol.for("react.provider"),gg=Symbol.for("react.context"),ie=Symbol.for("react.forward_ref"),ge=Symbol.for("react.suspense"),
he=Symbol.for("react.suspense_list"),je=Symbol.for("react.memo"),Ta=Symbol.for("react.lazy");Symbol.for("react.scope");Symbol.for("react.debug_trace_mode");var Ui=Symbol.for("react.offscreen");Symbol.for("react.legacy_hidden");Symbol.for("react.cache");Symbol.for("react.tracing_marker");var fg=Symbol.iterator,E=Object.assign,ae,ce=!1,cc=Array.isArray,Xd,yi=function(a){return"undefined"!==typeof MSApp&&MSApp.execUnsafeLocalFunction?function(b,c,d,e){MSApp.execUnsafeLocalFunction(function(){return a(b,
c,d,e)})}:a}(function(a,b){if("http://www.w3.org/2000/svg"!==a.namespaceURI||"innerHTML"in a)a.innerHTML=b;else{Xd=Xd||document.createElement("div");Xd.innerHTML="<svg>"+b.valueOf().toString()+"</svg>";for(b=Xd.firstChild;a.firstChild;)a.removeChild(a.firstChild);for(;b.firstChild;)a.appendChild(b.firstChild)}}),Fc=function(a,b){if(b){var c=a.firstChild;if(c&&c===a.lastChild&&3===c.nodeType){c.nodeValue=b;return}}a.textContent=b},dc={animationIterationCount:!0,aspectRatio:!0,borderImageOutset:!0,
borderImageSlice:!0,borderImageWidth:!0,boxFlex:!0,boxFlexGroup:!0,boxOrdinalGroup:!0,columnCount:!0,columns:!0,flex:!0,flexGrow:!0,flexPositive:!0,flexShrink:!0,flexNegative:!0,flexOrder:!0,gridArea:!0,gridRow:!0,gridRowEnd:!0,gridRowSpan:!0,gridRowStart:!0,gridColumn:!0,gridColumnEnd:!0,gridColumnSpan:!0,gridColumnStart:!0,fontWeight:!0,lineClamp:!0,lineHeight:!0,opacity:!0,order:!0,orphans:!0,tabSize:!0,widows:!0,zIndex:!0,zoom:!0,fillOpacity:!0,floodOpacity:!0,stopOpacity:!0,strokeDasharray:!0,
strokeDashoffset:!0,strokeMiterlimit:!0,strokeOpacity:!0,strokeWidth:!0},$k=["Webkit","ms","Moz","O"];Object.keys(dc).forEach(function(a){$k.forEach(function(b){b=b+a.charAt(0).toUpperCase()+a.substring(1);dc[b]=dc[a]})});var ij=E({menuitem:!0},{area:!0,base:!0,br:!0,col:!0,embed:!0,hr:!0,img:!0,input:!0,keygen:!0,link:!0,meta:!0,param:!0,source:!0,track:!0,wbr:!0}),ze=null,se=null,Eb=null,Fb=null,xg=function(a,b){return a(b)},yg=function(){},te=!1,Oe=!1;if(Ia)try{var Lc={};Object.defineProperty(Lc,
"passive",{get:function(){Oe=!0}});window.addEventListener("test",Lc,Lc);window.removeEventListener("test",Lc,Lc)}catch(a){Oe=!1}var kj=function(a,b,c,d,e,f,g,h,k){var l=Array.prototype.slice.call(arguments,3);try{b.apply(c,l)}catch(q){this.onError(q)}},gc=!1,Sc=null,Tc=!1,ue=null,lj={onError:function(a){gc=!0;Sc=a}},Ba=zb.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.Scheduler,Jg=Ba.unstable_scheduleCallback,Kg=Ba.unstable_NormalPriority,xh=Jg,Ki=Ba.unstable_cancelCallback,Pk=Ba.unstable_shouldYield,
Sk=Ba.unstable_requestPaint,P=Ba.unstable_now,Dj=Ba.unstable_getCurrentPriorityLevel,De=Ba.unstable_ImmediatePriority,Mg=Ba.unstable_UserBlockingPriority,ad=Kg,Ej=Ba.unstable_LowPriority,Ng=Ba.unstable_IdlePriority,Uc=null,Ca=null,ta=Math.clz32?Math.clz32:pj,qj=Math.log,rj=Math.LN2,Wc=64,Rd=4194304,z=0,Ae=!1,Yc=[],Va=null,Wa=null,Xa=null,jc=new Map,kc=new Map,Ya=[],Bj="mousedown mouseup touchcancel touchend touchstart auxclick dblclick pointercancel pointerdown pointerup dragend dragstart drop compositionend compositionstart keydown keypress keyup input textInput copy cut paste click change contextmenu reset submit".split(" "),
Gb=Sa.ReactCurrentBatchConfig,Zc=!0,$c=null,Za=null,Ee=null,bd=null,Yb={eventPhase:0,bubbles:0,cancelable:0,timeStamp:function(a){return a.timeStamp||Date.now()},defaultPrevented:0,isTrusted:0},He=ka(Yb),Mc=E({},Yb,{view:0,detail:0}),ak=ka(Mc),ag,bg,Nc,Yd=E({},Mc,{screenX:0,screenY:0,clientX:0,clientY:0,pageX:0,pageY:0,ctrlKey:0,shiftKey:0,altKey:0,metaKey:0,getModifierState:Fe,button:0,buttons:0,relatedTarget:function(a){return void 0===a.relatedTarget?a.fromElement===a.srcElement?a.toElement:a.fromElement:
a.relatedTarget},movementX:function(a){if("movementX"in a)return a.movementX;a!==Nc&&(Nc&&"mousemove"===a.type?(ag=a.screenX-Nc.screenX,bg=a.screenY-Nc.screenY):bg=ag=0,Nc=a);return ag},movementY:function(a){return"movementY"in a?a.movementY:bg}}),ih=ka(Yd),al=E({},Yd,{dataTransfer:0}),Wj=ka(al),bl=E({},Mc,{relatedTarget:0}),Pe=ka(bl),cl=E({},Yb,{animationName:0,elapsedTime:0,pseudoElement:0}),Yj=ka(cl),dl=E({},Yb,{clipboardData:function(a){return"clipboardData"in a?a.clipboardData:window.clipboardData}}),
ck=ka(dl),el=E({},Yb,{data:0}),qh=ka(el),fk=qh,fl={Esc:"Escape",Spacebar:" ",Left:"ArrowLeft",Up:"ArrowUp",Right:"ArrowRight",Down:"ArrowDown",Del:"Delete",Win:"OS",Menu:"ContextMenu",Apps:"ContextMenu",Scroll:"ScrollLock",MozPrintableKey:"Unidentified"},gl={8:"Backspace",9:"Tab",12:"Clear",13:"Enter",16:"Shift",17:"Control",18:"Alt",19:"Pause",20:"CapsLock",27:"Escape",32:" ",33:"PageUp",34:"PageDown",35:"End",36:"Home",37:"ArrowLeft",38:"ArrowUp",39:"ArrowRight",40:"ArrowDown",45:"Insert",46:"Delete",
112:"F1",113:"F2",114:"F3",115:"F4",116:"F5",117:"F6",118:"F7",119:"F8",120:"F9",121:"F10",122:"F11",123:"F12",144:"NumLock",145:"ScrollLock",224:"Meta"},Gj={Alt:"altKey",Control:"ctrlKey",Meta:"metaKey",Shift:"shiftKey"},hl=E({},Mc,{key:function(a){if(a.key){var b=fl[a.key]||a.key;if("Unidentified"!==b)return b}return"keypress"===a.type?(a=cd(a),13===a?"Enter":String.fromCharCode(a)):"keydown"===a.type||"keyup"===a.type?gl[a.keyCode]||"Unidentified":""},code:0,location:0,ctrlKey:0,shiftKey:0,altKey:0,
metaKey:0,repeat:0,locale:0,getModifierState:Fe,charCode:function(a){return"keypress"===a.type?cd(a):0},keyCode:function(a){return"keydown"===a.type||"keyup"===a.type?a.keyCode:0},which:function(a){return"keypress"===a.type?cd(a):"keydown"===a.type||"keyup"===a.type?a.keyCode:0}}),Vj=ka(hl),il=E({},Yd,{pointerId:0,width:0,height:0,pressure:0,tangentialPressure:0,tiltX:0,tiltY:0,twist:0,pointerType:0,isPrimary:0}),nh=ka(il),jl=E({},Mc,{touches:0,targetTouches:0,changedTouches:0,altKey:0,metaKey:0,
ctrlKey:0,shiftKey:0,getModifierState:Fe}),Xj=ka(jl),kl=E({},Yb,{propertyName:0,elapsedTime:0,pseudoElement:0}),Zj=ka(kl),ll=E({},Yd,{deltaX:function(a){return"deltaX"in a?a.deltaX:"wheelDeltaX"in a?-a.wheelDeltaX:0},deltaY:function(a){return"deltaY"in a?a.deltaY:"wheelDeltaY"in a?-a.wheelDeltaY:"wheelDelta"in a?-a.wheelDelta:0},deltaZ:0,deltaMode:0}),bk=ka(ll),Hj=[9,13,27,32],Ge=Ia&&"CompositionEvent"in window,Oc=null;Ia&&"documentMode"in document&&(Oc=document.documentMode);var ek=Ia&&"TextEvent"in
window&&!Oc,Ug=Ia&&(!Ge||Oc&&8<Oc&&11>=Oc),Tg=String.fromCharCode(32),Sg=!1,Hb=!1,Kj={color:!0,date:!0,datetime:!0,"datetime-local":!0,email:!0,month:!0,number:!0,password:!0,range:!0,search:!0,tel:!0,text:!0,time:!0,url:!0,week:!0},oc=null,pc=null,ph=!1;Ia&&(ph=Lj("input")&&(!document.documentMode||9<document.documentMode));var ua="function"===typeof Object.is?Object.is:Sj,dk=Ia&&"documentMode"in document&&11>=document.documentMode,Jb=null,Ke=null,rc=null,Je=!1,Kb={animationend:gd("Animation","AnimationEnd"),
animationiteration:gd("Animation","AnimationIteration"),animationstart:gd("Animation","AnimationStart"),transitionend:gd("Transition","TransitionEnd")},Le={},eh={};Ia&&(eh=document.createElement("div").style,"AnimationEvent"in window||(delete Kb.animationend.animation,delete Kb.animationiteration.animation,delete Kb.animationstart.animation),"TransitionEvent"in window||delete Kb.transitionend.transition);var jh=hd("animationend"),kh=hd("animationiteration"),lh=hd("animationstart"),mh=hd("transitionend"),
fh=new Map,Zi="abort auxClick cancel canPlay canPlayThrough click close contextMenu copy cut drag dragEnd dragEnter dragExit dragLeave dragOver dragStart drop durationChange emptied encrypted ended error gotPointerCapture input invalid keyDown keyPress keyUp load loadedData loadedMetadata loadStart lostPointerCapture mouseDown mouseMove mouseOut mouseOver mouseUp paste pause play playing pointerCancel pointerDown pointerMove pointerOut pointerOver pointerUp progress rateChange reset resize seeked seeking stalled submit suspend timeUpdate touchCancel touchEnd touchStart volumeChange scroll toggle touchMove waiting wheel".split(" ");
(function(){for(var a=0;a<Zi.length;a++){var b=Zi[a],c=b.toLowerCase();b=b[0].toUpperCase()+b.slice(1);$a(c,"on"+b)}$a(jh,"onAnimationEnd");$a(kh,"onAnimationIteration");$a(lh,"onAnimationStart");$a("dblclick","onDoubleClick");$a("focusin","onFocus");$a("focusout","onBlur");$a(mh,"onTransitionEnd")})();Ab("onMouseEnter",["mouseout","mouseover"]);Ab("onMouseLeave",["mouseout","mouseover"]);Ab("onPointerEnter",["pointerout","pointerover"]);Ab("onPointerLeave",["pointerout","pointerover"]);mb("onChange",
"change click focusin focusout input keydown keyup selectionchange".split(" "));mb("onSelect","focusout contextmenu dragend focusin keydown keyup mousedown mouseup selectionchange".split(" "));mb("onBeforeInput",["compositionend","keypress","textInput","paste"]);mb("onCompositionEnd","compositionend focusout keydown keypress keyup mousedown".split(" "));mb("onCompositionStart","compositionstart focusout keydown keypress keyup mousedown".split(" "));mb("onCompositionUpdate","compositionupdate focusout keydown keypress keyup mousedown".split(" "));
var Ec="abort canplay canplaythrough durationchange emptied encrypted ended error loadeddata loadedmetadata loadstart pause play playing progress ratechange resize seeked seeking stalled suspend timeupdate volumechange waiting".split(" "),Uj=new Set("cancel close invalid load scroll toggle".split(" ").concat(Ec)),id="_reactListening"+Math.random().toString(36).slice(2),gk=/\\r\\n?/g,hk=/\\u0000|\\uFFFD/g,Jf=null,Kf=null,Rf="function"===typeof setTimeout?setTimeout:void 0,Nk="function"===typeof clearTimeout?
clearTimeout:void 0,$i="function"===typeof Promise?Promise:void 0,Jk="function"===typeof queueMicrotask?queueMicrotask:"undefined"!==typeof $i?function(a){return $i.resolve(null).then(a).catch(ik)}:Rf,Zb=Math.random().toString(36).slice(2),Da="__reactFiber$"+Zb,uc="__reactProps$"+Zb,Ja="__reactContainer$"+Zb,Me="__reactEvents$"+Zb,Dk="__reactListeners$"+Zb,Ek="__reactHandles$"+Zb,Se=[],Mb=-1,cb={},J=bb(cb),S=bb(!1),pb=cb,La=null,md=!1,Te=!1,Ob=[],Pb=0,od=null,nd=0,na=[],oa=0,rb=null,Ma=1,Na="",la=
null,fa=null,D=!1,wa=null,Ik=Sa.ReactCurrentBatchConfig,Vb=Dh(!0),li=Dh(!1),ud=bb(null),td=null,Rb=null,bf=null,tb=null,kk=Oa,gb=!1,wc={},Ea=bb(wc),yc=bb(wc),xc=bb(wc),F=bb(0),kf=[],yd=Sa.ReactCurrentDispatcher,sf=Sa.ReactCurrentBatchConfig,vb=0,C=null,K=null,N=null,Ad=!1,zc=!1,Ac=0,ml=0,zd={readContext:qa,useCallback:V,useContext:V,useEffect:V,useImperativeHandle:V,useInsertionEffect:V,useLayoutEffect:V,useMemo:V,useReducer:V,useRef:V,useState:V,useDebugValue:V,useDeferredValue:V,useTransition:V,
useMutableSource:V,useSyncExternalStore:V,useId:V,unstable_isNewReconciler:!1},lk={readContext:qa,useCallback:function(a,b){Fa().memoizedState=[a,void 0===b?null:b];return a},useContext:qa,useEffect:Sh,useImperativeHandle:function(a,b,c){c=null!==c&&void 0!==c?c.concat([a]):null;return Bd(4194308,4,Vh.bind(null,b,a),c)},useLayoutEffect:function(a,b){return Bd(4194308,4,a,b)},useInsertionEffect:function(a,b){return Bd(4,2,a,b)},useMemo:function(a,b){var c=Fa();b=void 0===b?null:b;a=a();c.memoizedState=
[a,b];return a},useReducer:function(a,b,c){var d=Fa();b=void 0!==c?c(b):b;d.memoizedState=d.baseState=b;a={pending:null,interleaved:null,lanes:0,dispatch:null,lastRenderedReducer:a,lastRenderedState:b};d.queue=a;a=a.dispatch=qk.bind(null,C,a);return[d.memoizedState,a]},useRef:function(a){var b=Fa();a={current:a};return b.memoizedState=a},useState:Qh,useDebugValue:rf,useDeferredValue:function(a){return Fa().memoizedState=a},useTransition:function(){var a=Qh(!1),b=a[0];a=pk.bind(null,a[1]);Fa().memoizedState=
a;return[b,a]},useMutableSource:function(a,b,c){},useSyncExternalStore:function(a,b,c){var d=C,e=Fa();if(D){if(void 0===c)throw Error(m(407));c=c()}else{c=b();if(null===O)throw Error(m(349));0!==(vb&30)||Nh(d,b,c)}e.memoizedState=c;var f={value:c,getSnapshot:b};e.queue=f;Sh(Lh.bind(null,d,f,a),[a]);d.flags|=2048;Cc(9,Mh.bind(null,d,f,c,b),void 0,null);return c},useId:function(){var a=Fa(),b=O.identifierPrefix;if(D){var c=Na;var d=Ma;c=(d&~(1<<32-ta(d)-1)).toString(32)+c;b=":"+b+"R"+c;c=Ac++;0<c&&
(b+="H"+c.toString(32));b+=":"}else c=ml++,b=":"+b+"r"+c.toString(32)+":";return a.memoizedState=b},unstable_isNewReconciler:!1},mk={readContext:qa,useCallback:Xh,useContext:qa,useEffect:qf,useImperativeHandle:Wh,useInsertionEffect:Th,useLayoutEffect:Uh,useMemo:Yh,useReducer:of,useRef:Rh,useState:function(a){return of(Bc)},useDebugValue:rf,useDeferredValue:function(a){var b=sa();return Zh(b,K.memoizedState,a)},useTransition:function(){var a=of(Bc)[0],b=sa().memoizedState;return[a,b]},useMutableSource:Jh,
useSyncExternalStore:Kh,useId:$h,unstable_isNewReconciler:!1},nk={readContext:qa,useCallback:Xh,useContext:qa,useEffect:qf,useImperativeHandle:Wh,useInsertionEffect:Th,useLayoutEffect:Uh,useMemo:Yh,useReducer:pf,useRef:Rh,useState:function(a){return pf(Bc)},useDebugValue:rf,useDeferredValue:function(a){var b=sa();return null===K?b.memoizedState=a:Zh(b,K.memoizedState,a)},useTransition:function(){var a=pf(Bc)[0],b=sa().memoizedState;return[a,b]},useMutableSource:Jh,useSyncExternalStore:Kh,useId:$h,
unstable_isNewReconciler:!1},Dd={isMounted:function(a){return(a=a._reactInternals)?nb(a)===a:!1},enqueueSetState:function(a,b,c){a=a._reactInternals;var d=Z(),e=hb(a),f=Pa(d,e);f.payload=b;void 0!==c&&null!==c&&(f.callback=c);b=fb(a,f,e);null!==b&&(xa(b,a,e,d),vd(b,a,e))},enqueueReplaceState:function(a,b,c){a=a._reactInternals;var d=Z(),e=hb(a),f=Pa(d,e);f.tag=1;f.payload=b;void 0!==c&&null!==c&&(f.callback=c);b=fb(a,f,e);null!==b&&(xa(b,a,e,d),vd(b,a,e))},enqueueForceUpdate:function(a,b){a=a._reactInternals;
var c=Z(),d=hb(a),e=Pa(c,d);e.tag=2;void 0!==b&&null!==b&&(e.callback=b);b=fb(a,e,d);null!==b&&(xa(b,a,d,c),vd(b,a,d))}},rk="function"===typeof WeakMap?WeakMap:Map,tk=Sa.ReactCurrentOwner,ha=!1,Cf={dehydrated:null,treeContext:null,retryLane:0};var zk=function(a,b,c,d){for(c=b.child;null!==c;){if(5===c.tag||6===c.tag)a.appendChild(c.stateNode);else if(4!==c.tag&&null!==c.child){c.child.return=c;c=c.child;continue}if(c===b)break;for(;null===c.sibling;){if(null===c.return||c.return===b)return;c=c.return}c.sibling.return=
c.return;c=c.sibling}};var xi=function(a,b){};var yk=function(a,b,c,d,e){var f=a.memoizedProps;if(f!==d){a=b.stateNode;ub(Ea.current);e=null;switch(c){case "input":f=ke(a,f);d=ke(a,d);e=[];break;case "select":f=E({},f,{value:void 0});d=E({},d,{value:void 0});e=[];break;case "textarea":f=ne(a,f);d=ne(a,d);e=[];break;default:"function"!==typeof f.onClick&&"function"===typeof d.onClick&&(a.onclick=kd)}pe(c,d);var g;c=null;for(l in f)if(!d.hasOwnProperty(l)&&f.hasOwnProperty(l)&&null!=f[l])if("style"===
l){var h=f[l];for(g in h)h.hasOwnProperty(g)&&(c||(c={}),c[g]="")}else"dangerouslySetInnerHTML"!==l&&"children"!==l&&"suppressContentEditableWarning"!==l&&"suppressHydrationWarning"!==l&&"autoFocus"!==l&&($b.hasOwnProperty(l)?e||(e=[]):(e=e||[]).push(l,null));for(l in d){var k=d[l];h=null!=f?f[l]:void 0;if(d.hasOwnProperty(l)&&k!==h&&(null!=k||null!=h))if("style"===l)if(h){for(g in h)!h.hasOwnProperty(g)||k&&k.hasOwnProperty(g)||(c||(c={}),c[g]="");for(g in k)k.hasOwnProperty(g)&&h[g]!==k[g]&&(c||
(c={}),c[g]=k[g])}else c||(e||(e=[]),e.push(l,c)),c=k;else"dangerouslySetInnerHTML"===l?(k=k?k.__html:void 0,h=h?h.__html:void 0,null!=k&&h!==k&&(e=e||[]).push(l,k)):"children"===l?"string"!==typeof k&&"number"!==typeof k||(e=e||[]).push(l,""+k):"suppressContentEditableWarning"!==l&&"suppressHydrationWarning"!==l&&($b.hasOwnProperty(l)?(null!=k&&"onScroll"===l&&B("scroll",a),e||h===k||(e=[])):(e=e||[]).push(l,k))}c&&(e=e||[]).push("style",c);var l=e;if(b.updateQueue=l)b.flags|=4}};var Ak=function(a,
b,c,d){c!==d&&(b.flags|=4)};var Jd=!1,X=!1,Fk="function"===typeof WeakSet?WeakSet:Set,l=null,zi=!1,T=null,za=!1,Mk=Math.ceil,Od=Sa.ReactCurrentDispatcher,Uf=Sa.ReactCurrentOwner,ca=Sa.ReactCurrentBatchConfig,p=0,O=null,H=null,U=0,ba=0,Ga=bb(0),L=0,Jc=null,ra=0,Md=0,Sf=0,Kc=null,ja=null,Of=0,Hf=Infinity,Ra=null,Ed=!1,xf=null,ib=null,Pd=!1,lb=null,Qd=0,Ic=0,Pf=null,Kd=-1,Ld=0;var Qk=function(a,b,c){if(null!==a)if(a.memoizedProps!==b.pendingProps||S.current)ha=!0;else{if(0===(a.lanes&c)&&0===(b.flags&
128))return ha=!1,wk(a,b,c);ha=0!==(a.flags&131072)?!0:!1}else ha=!1,D&&0!==(b.flags&1048576)&&yh(b,nd,b.index);b.lanes=0;switch(b.tag){case 2:var d=b.type;Fd(a,b);a=b.pendingProps;var e=Nb(b,J.current);Sb(b,c);e=mf(null,b,d,a,e,c);var f=nf();b.flags|=1;"object"===typeof e&&null!==e&&"function"===typeof e.render&&void 0===e.$$typeof?(b.tag=1,b.memoizedState=null,b.updateQueue=null,ea(d)?(f=!0,ld(b)):f=!1,b.memoizedState=null!==e.state&&void 0!==e.state?e.state:null,ff(b),e.updater=Dd,b.stateNode=
e,e._reactInternals=b,uf(b,d,a,c),b=Af(null,b,d,!0,f,c)):(b.tag=0,D&&f&&Ue(b),aa(null,b,e,c),b=b.child);return b;case 16:d=b.elementType;a:{Fd(a,b);a=b.pendingProps;e=d._init;d=e(d._payload);b.type=d;e=b.tag=Uk(d);a=ya(d,a);switch(e){case 0:b=zf(null,b,d,a,c);break a;case 1:b=ri(null,b,d,a,c);break a;case 11:b=mi(null,b,d,a,c);break a;case 14:b=ni(null,b,d,ya(d.type,a),c);break a}throw Error(m(306,d,""));}return b;case 0:return d=b.type,e=b.pendingProps,e=b.elementType===d?e:ya(d,e),zf(a,b,d,e,c);
case 1:return d=b.type,e=b.pendingProps,e=b.elementType===d?e:ya(d,e),ri(a,b,d,e,c);case 3:a:{si(b);if(null===a)throw Error(m(387));d=b.pendingProps;f=b.memoizedState;e=f.element;Fh(a,b);wd(b,d,null,c);var g=b.memoizedState;d=g.element;if(f.isDehydrated)if(f={element:d,isDehydrated:!1,cache:g.cache,pendingSuspenseBoundaries:g.pendingSuspenseBoundaries,transitions:g.transitions},b.updateQueue.baseState=f,b.memoizedState=f,b.flags&256){e=Ub(Error(m(423)),b);b=ti(a,b,d,c,e);break a}else if(d!==e){e=
Ub(Error(m(424)),b);b=ti(a,b,d,c,e);break a}else for(fa=Ka(b.stateNode.containerInfo.firstChild),la=b,D=!0,wa=null,c=li(b,null,d,c),b.child=c;c;)c.flags=c.flags&-3|4096,c=c.sibling;else{Qb();if(d===e){b=Qa(a,b,c);break a}aa(a,b,d,c)}b=b.child}return b;case 5:return Ih(b),null===a&&Xe(b),d=b.type,e=b.pendingProps,f=null!==a?a.memoizedProps:null,g=e.children,Qe(d,e)?g=null:null!==f&&Qe(d,f)&&(b.flags|=32),qi(a,b),aa(a,b,g,c),b.child;case 6:return null===a&&Xe(b),null;case 13:return ui(a,b,c);case 4:return gf(b,
b.stateNode.containerInfo),d=b.pendingProps,null===a?b.child=Vb(b,null,d,c):aa(a,b,d,c),b.child;case 11:return d=b.type,e=b.pendingProps,e=b.elementType===d?e:ya(d,e),mi(a,b,d,e,c);case 7:return aa(a,b,b.pendingProps,c),b.child;case 8:return aa(a,b,b.pendingProps.children,c),b.child;case 12:return aa(a,b,b.pendingProps.children,c),b.child;case 10:a:{d=b.type._context;e=b.pendingProps;f=b.memoizedProps;g=e.value;y(ud,d._currentValue);d._currentValue=g;if(null!==f)if(ua(f.value,g)){if(f.children===
e.children&&!S.current){b=Qa(a,b,c);break a}}else for(f=b.child,null!==f&&(f.return=b);null!==f;){var h=f.dependencies;if(null!==h){g=f.child;for(var k=h.firstContext;null!==k;){if(k.context===d){if(1===f.tag){k=Pa(-1,c&-c);k.tag=2;var l=f.updateQueue;if(null!==l){l=l.shared;var p=l.pending;null===p?k.next=k:(k.next=p.next,p.next=k);l.pending=k}}f.lanes|=c;k=f.alternate;null!==k&&(k.lanes|=c);df(f.return,c,b);h.lanes|=c;break}k=k.next}}else if(10===f.tag)g=f.type===b.type?null:f.child;else if(18===
f.tag){g=f.return;if(null===g)throw Error(m(341));g.lanes|=c;h=g.alternate;null!==h&&(h.lanes|=c);df(g,c,b);g=f.sibling}else g=f.child;if(null!==g)g.return=f;else for(g=f;null!==g;){if(g===b){g=null;break}f=g.sibling;if(null!==f){f.return=g.return;g=f;break}g=g.return}f=g}aa(a,b,e.children,c);b=b.child}return b;case 9:return e=b.type,d=b.pendingProps.children,Sb(b,c),e=qa(e),d=d(e),b.flags|=1,aa(a,b,d,c),b.child;case 14:return d=b.type,e=ya(d,b.pendingProps),e=ya(d.type,e),ni(a,b,d,e,c);case 15:return oi(a,
b,b.type,b.pendingProps,c);case 17:return d=b.type,e=b.pendingProps,e=b.elementType===d?e:ya(d,e),Fd(a,b),b.tag=1,ea(d)?(a=!0,ld(b)):a=!1,Sb(b,c),ei(b,d,e),uf(b,d,e,c),Af(null,b,d,!0,a,c);case 19:return wi(a,b,c);case 22:return pi(a,b,c)}throw Error(m(156,b.tag));};var pa=function(a,b,c,d){return new Tk(a,b,c,d)},aj="function"===typeof reportError?reportError:function(a){console.error(a)};Ud.prototype.render=Xf.prototype.render=function(a){var b=this._internalRoot;if(null===b)throw Error(m(409));
Sd(a,b,null,null)};Ud.prototype.unmount=Xf.prototype.unmount=function(){var a=this._internalRoot;if(null!==a){this._internalRoot=null;var b=a.containerInfo;yb(function(){Sd(null,a,null,null)});b[Ja]=null}};Ud.prototype.unstable_scheduleHydration=function(a){if(a){var b=nl();a={blockedOn:null,target:a,priority:b};for(var c=0;c<Ya.length&&0!==b&&b<Ya[c].priority;c++);Ya.splice(c,0,a);0===c&&Hg(a)}};var Cj=function(a){switch(a.tag){case 3:var b=a.stateNode;if(b.current.memoizedState.isDehydrated){var c=
hc(b.pendingLanes);0!==c&&(xe(b,c|1),ia(b,P()),0===(p&6)&&(Hc(),db()))}break;case 13:yb(function(){var b=Oa(a,1);if(null!==b){var c=Z();xa(b,a,1,c)}}),Wf(a,1)}};var Gg=function(a){if(13===a.tag){var b=Oa(a,134217728);if(null!==b){var c=Z();xa(b,a,134217728,c)}Wf(a,134217728)}};var xj=function(a){if(13===a.tag){var b=hb(a),c=Oa(a,b);if(null!==c){var d=Z();xa(c,a,b,d)}Wf(a,b)}};var nl=function(){return z};var wj=function(a,b){var c=z;try{return z=a,b()}finally{z=c}};se=function(a,b,c){switch(b){case "input":le(a,
c);b=c.name;if("radio"===c.type&&null!=b){for(c=a;c.parentNode;)c=c.parentNode;c=c.querySelectorAll("input[name="+JSON.stringify(""+b)+'][type="radio"]');for(b=0;b<c.length;b++){var d=c[b];if(d!==a&&d.form===a.form){var e=Rc(d);if(!e)throw Error(m(90));jg(d);le(d,e)}}}break;case "textarea":og(a,c);break;case "select":b=c.value,null!=b&&Db(a,!!c.multiple,b,!1)}};(function(a,b,c){xg=a;yg=c})(Tf,function(a,b,c,d,e){var f=z,g=ca.transition;try{return ca.transition=null,z=1,a(b,c,d,e)}finally{z=f,ca.transition=
g,0===p&&Hc()}},yb);var ol={usingClientEntryPoint:!1,Events:[ec,Ib,Rc,ug,vg,Tf]};(function(a){a={bundleType:a.bundleType,version:a.version,rendererPackageName:a.rendererPackageName,rendererConfig:a.rendererConfig,overrideHookState:null,overrideHookStateDeletePath:null,overrideHookStateRenamePath:null,overrideProps:null,overridePropsDeletePath:null,overridePropsRenamePath:null,setErrorHandler:null,setSuspenseHandler:null,scheduleUpdate:null,currentDispatcherRef:Sa.ReactCurrentDispatcher,findHostInstanceByFiber:Xk,
findFiberByHostInstance:a.findFiberByHostInstance||Yk,findHostInstancesForRefresh:null,scheduleRefresh:null,scheduleRoot:null,setRefreshHandler:null,getCurrentFiber:null,reconcilerVersion:"18.3.1"};if("undefined"===typeof __REACT_DEVTOOLS_GLOBAL_HOOK__)a=!1;else{var b=__REACT_DEVTOOLS_GLOBAL_HOOK__;if(b.isDisabled||!b.supportsFiber)a=!0;else{try{Uc=b.inject(a),Ca=b}catch(c){}a=b.checkDCE?!0:!1}}return a})({findFiberByHostInstance:ob,bundleType:0,version:"18.3.1-next-f1338f8080-20240426",
rendererPackageName:"react-dom"});Q.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED=ol;Q.createPortal=function(a,b){var c=2<arguments.length&&void 0!==arguments[2]?arguments[2]:null;if(!Yf(b))throw Error(m(200));return Wk(a,b,null,c)};Q.createRoot=function(a,b){if(!Yf(a))throw Error(m(299));var c=!1,d="",e=aj;null!==b&&void 0!==b&&(!0===b.unstable_strictMode&&(c=!0),void 0!==b.identifierPrefix&&(d=b.identifierPrefix),void 0!==b.onRecoverableError&&(e=b.onRecoverableError));b=Vf(a,1,!1,null,null,
c,!1,d,e);a[Ja]=b.current;sc(8===a.nodeType?a.parentNode:a);return new Xf(b)};Q.findDOMNode=function(a){if(null==a)return null;if(1===a.nodeType)return a;var b=a._reactInternals;if(void 0===b){if("function"===typeof a.render)throw Error(m(188));a=Object.keys(a).join(",");throw Error(m(268,a));}a=Bg(b);a=null===a?null:a.stateNode;return a};Q.flushSync=function(a){return yb(a)};Q.hydrate=function(a,b,c){if(!Vd(b))throw Error(m(200));return Wd(null,a,b,!0,c)};Q.hydrateRoot=function(a,b,c){if(!Yf(a))throw Error(m(405));
var d=null!=c&&c.hydratedSources||null,e=!1,f="",g=aj;null!==c&&void 0!==c&&(!0===c.unstable_strictMode&&(e=!0),void 0!==c.identifierPrefix&&(f=c.identifierPrefix),void 0!==c.onRecoverableError&&(g=c.onRecoverableError));b=Wi(b,null,a,1,null!=c?c:null,e,!1,f,g);a[Ja]=b.current;sc(a);if(d)for(a=0;a<d.length;a++)c=d[a],e=c._getVersion,e=e(c._source),null==b.mutableSourceEagerHydrationData?b.mutableSourceEagerHydrationData=[c,e]:b.mutableSourceEagerHydrationData.push(c,e);return new Ud(b)};Q.render=
function(a,b,c){if(!Vd(b))throw Error(m(200));return Wd(null,a,b,!1,c)};Q.unmountComponentAtNode=function(a){if(!Vd(a))throw Error(m(40));return a._reactRootContainer?(yb(function(){Wd(null,null,a,!1,function(){a._reactRootContainer=null;a[Ja]=null})}),!0):!1};Q.unstable_batchedUpdates=Tf;Q.unstable_renderSubtreeIntoContainer=function(a,b,c,d){if(!Vd(c))throw Error(m(200));if(null==a||void 0===a._reactInternals)throw Error(m(38));return Wd(a,b,c,!1,d)};Q.version="18.3.1-next-f1338f8080-20240426"});
})();

</script>
<script>
(function(){
  function showBootErr(msg){
    var el=document.getElementById("root");
    if(el) el.innerHTML='<div style="padding:24px;font-family:sans-serif;font-weight:800;border:3px solid #000;background:#fecaca;margin:16px;max-width:520px">'+msg+'</div>';
  }
  if(!window.React||!window.ReactDOM){ showBootErr("React failed to init"); return; }
  try {
const {
  useState,
  useEffect,
  useCallback,
  useRef
} = React;
function showToast(text, type) {
  var kind = "info";
  if (type === true || type === "error" || type === "err") kind = "error";
  else if (type === "success" || type === "ok") kind = "success";
  else if (type === "ping") kind = "ping";
  else if (type === "copy") kind = "copy";
  else if (type === false || type == null || type === "info") kind = "info";
  else if (typeof type === "string") kind = type;
  var icons = {
    error: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>',
    success: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="M22 4L12 14.01l-3-3"/></svg>',
    ping: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.5"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><circle cx="12" cy="20" r="1.2" fill="#000" stroke="none"/></svg>',
    copy: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
    info: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.4"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/></svg>'
  };
  var colors = { error: "#fda4af", success: "#facc15", ping: "#fb923c", copy: "#fde047", info: "#fde68a" };
  var bars = { error: "#e11d48", success: "#ca8a04", ping: "#ea580c", copy: "#eab308", info: "#ca8a04" };
  var wrap = document.getElementById("toast-wrap");
  if (!wrap) return;
  while (wrap.children.length >= 5) {
    try { wrap.removeChild(wrap.firstChild); } catch (e) { break; }
  }
  var t = document.createElement("div");
  t.className = "tb-toast" + (kind === "error" ? " err" : "");
  t.style.cssText = "display:flex;align-items:center;gap:10px;background:" + (colors[kind]||"#fff") + ";border:3px solid #000;box-shadow:4px 4px 0 #000;padding:12px 14px;font-weight:800;font-size:13px;max-width:min(400px,92vw);opacity:0;transform:translateY(12px);transition:opacity .2s,transform .25s;position:relative;overflow:hidden;";
  t.innerHTML = '<span style="position:absolute;top:0;left:0;right:0;height:4px;background:' + (bars[kind]||"#facc15") + ';border-bottom:2px solid #000"></span><span style="width:32px;height:32px;border:2.5px solid #000;background:#fff;display:inline-flex;align-items:center;justify-content:center;box-shadow:2px 2px 0 #000;flex-shrink:0">' + (icons[kind]||icons.info) + '</span><span style="flex:1;line-height:1.35"></span>';
  t.querySelector("span:last-child").textContent = text;
  wrap.appendChild(t);
  // older toasts fade (stack of up to 5)
  for (var si = 0; si < wrap.children.length; si++) {
    var age = wrap.children.length - 1 - si;
    var op = Math.max(0.35, 1 - age * 0.14);
    wrap.children[si].style.opacity = String(op);
  }
  requestAnimationFrame(function () { t.classList.add("show"); t.style.opacity = "1"; t.style.transform = "translateY(0)"; });
  setTimeout(function () {
    t.style.opacity = "0";
    t.style.transform = "translateY(10px)";
    setTimeout(function () { try { t.remove(); } catch (e) {} }, 250);
  }, 2600);
}
function showConfirm(message, onYes, onNo) {
  var existing = document.getElementById("tb-confirm-overlay");
  if (existing) try { existing.remove(); } catch (e) {}
  var overlay = document.createElement("div");
  overlay.id = "tb-confirm-overlay";
  overlay.style.cssText = "position:fixed;inset:0;z-index:10000;background:rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center;padding:16px;";
  var box = document.createElement("div");
  box.style.cssText = "background:#fffdf5;border:3.5px solid #000;box-shadow:6px 6px 0 #000;max-width:360px;width:100%;padding:20px 18px;font-family:Public Sans,sans-serif;";
  var title = document.createElement("div");
  title.style.cssText = "font-family:Archivo,sans-serif;font-weight:900;font-size:1.1rem;margin-bottom:8px";
  title.textContent = "Confirm";
  var msg = document.createElement("div");
  msg.style.cssText = "font-weight:700;font-size:.9rem;color:#3f3f46;margin-bottom:18px;line-height:1.45";
  msg.textContent = message;
  var row = document.createElement("div");
  row.style.cssText = "display:flex;gap:10px";
  var btnNo = document.createElement("button");
  btnNo.type = "button";
  btnNo.textContent = "Cancel";
  btnNo.style.cssText = "flex:1;min-height:44px;font-weight:800;border:2.5px solid #000;background:#fff;box-shadow:3px 3px 0 #000;cursor:pointer;font-family:inherit";
  var btnYes = document.createElement("button");
  btnYes.type = "button";
  btnYes.textContent = "Yes";
  btnYes.style.cssText = "flex:1;min-height:44px;font-weight:800;border:2.5px solid #000;background:#facc15;box-shadow:3px 3px 0 #000;cursor:pointer;font-family:inherit";
  function close() { try { overlay.remove(); } catch (e) {} }
  btnNo.onclick = function () { close(); if (onNo) onNo(); };
  btnYes.onclick = function () { close(); if (onYes) onYes(); };
  overlay.onclick = function (e) { if (e.target === overlay) { close(); if (onNo) onNo(); } };
  row.appendChild(btnNo);
  row.appendChild(btnYes);
  box.appendChild(title);
  box.appendChild(msg);
  box.appendChild(row);
  overlay.appendChild(box);
  document.body.appendChild(overlay);
}
function fmtTraffic(gb) {
  if (gb == null || gb === undefined || gb === "") return "∞";
  var n = Number(gb);
  if (!isFinite(n) || n < 0) return "—";
  if (n === 0) return "0";
  var bytes = n * 1024 * 1024 * 1024;
  if (bytes < 1024) return Math.max(1, Math.round(bytes)) + " B";
  var kb = bytes / 1024;
  if (kb < 1024) return (kb < 10 ? kb.toFixed(1) : Math.round(kb)) + " KB";
  var mb = kb / 1024;
  if (mb < 1024) {
    if (mb < 10) return mb.toFixed(2) + " MB";
    if (mb < 100) return mb.toFixed(1) + " MB";
    return Math.round(mb) + " MB";
  }
  var g = mb / 1024;
  if (g < 10) return g.toFixed(2) + " GB";
  if (g < 100) return g.toFixed(1) + " GB";
  return Math.round(g) + " GB";
}
async function copyText(s) {
  try {
    await navigator.clipboard.writeText(s);
    return true;
  } catch (e) {
    return false;
  }
}
const BlackStar = ({
  size = 14
}) => /*#__PURE__*/React.createElement("svg", {
  width: size,
  height: size,
  viewBox: "0 0 24 24",
  fill: "#000"
}, /*#__PURE__*/React.createElement("path", {
  d: "M12 2l2.4 7.2H22l-6 4.8 2.3 7.2L12 16.8 5.7 21.2 8 14 2 9.2h7.6L12 2z"
}));
const TLS_PORTS = ["443", "2053", "2083", "2087", "2096", "8443"];
const NONTLS_PORTS = ["80", "8080", "8880", "2052", "2086", "2095"];
const FINGERPRINTS = ["chrome", "firefox", "safari", "ios", "android", "edge", "qq", "360", "random", "randomized"];
const OPERATORS_FALLBACK = [{ key: "all", label: "All", count: 0 }];

const VIP_COUNTRIES = ["DE", "US", "NL", "GB", "FR", "TR", "FI", "SE", "CA", "JP"];
const SAMPLE_IPS = {
  all: ["104.21.12.34", "172.67.45.67", "104.18.90.12", "162.159.1.10", "104.16.55.22", "104.19.88.3", "172.66.40.9"],
  IRANCELL: ["172.67.80.190", "104.16.36.165", "104.18.250.213"],
  RIGHTEL: ["104.17.52.109", "104.27.38.72", "172.67.121.18"],
  SHATEL: ["104.21.88.11", "172.66.40.20"],
  MCI: ["104.19.100.50", "162.159.134.20"],
  TELECOM: ["104.18.200.10"],
  APTEL: ["172.67.10.5"],
  SAMANTEL: ["104.25.30.8"],
  PISHGAMAN: ["104.16.90.3"],
  FIBER: ["172.64.100.2"],
  ASIATECH: ["104.21.50.9", "162.159.200.1"]
};
function TrexBridgePanel() {
  const [activeTab, setActiveTab] = useState("home");
  const [toast, setToast] = useState(null);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editUser, setEditUser] = useState(null);
  const [stats, setStats] = useState({
    total: 0,
    online: 0,
    active: 0,
    usage: 0,
    requestsToday: 0,
    requestsLimit: 100000
  });
  const timer = useRef(null);
  const showToastLocal = (msg, type) => {
    showToast(msg, type);
    setToast(msg);
    setTimeout(() => setToast(null), 2200);
  };
  const loadUsers = useCallback(async silent => {
    try {
      if (!silent) setLoading(true);
      const res = await fetch("/api/users?t=" + Date.now(), {
        credentials: "same-origin"
      });
      if (res.status === 401) {
        location.replace("/login");
        return;
      }
      if (!res.ok) throw new Error("fail");
      const data = await res.json();
      const list = Array.isArray(data) ? data : data.users || data.results || [];
      setUsers(list);
      const now = Date.now();
      let online = 0,
        active = 0,
        usage = 0;
      list.forEach(u => {
        usage += parseFloat(u.used_gb) || 0;
        if (u.is_active) active++;
        const on = (u.online_count > 0) || u.is_online === 1 || (u.last_active && now - Number(u.last_active) < 60000);
        if (on) online++;
      });
      const reqToday = data.cfRequestsToday != null ? data.cfRequestsToday : (data.reqsToday != null ? data.reqsToday : 0);
      const reqLimit = data.cfRequestsLimit != null ? data.cfRequestsLimit : 100000;
      setStats({
        total: list.length,
        online,
        active,
        usage,
        requestsToday: Number(reqToday) || 0,
        requestsLimit: Number(reqLimit) || 100000
      });
    } catch (e) {
      if (!silent) showToast("Failed to load users", true);
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);
  useEffect(() => {
    loadUsers(false);
    timer.current = setInterval(() => {
      if (!document.hidden) loadUsers(true);
    }, 12000);
    return () => clearInterval(timer.current);
  }, [loadUsers]);
  const reqPct = Math.min(100, stats.requestsLimit > 0 ? stats.requestsToday / stats.requestsLimit * 100 : 0);
  const fmtUsage = gb => fmtTraffic(gb);
  return /*#__PURE__*/React.createElement("div", {
    className: "content-wrap min-h-screen pb-28"
  }, /*#__PURE__*/React.createElement("header", {
    className: "glass-header sticky top-0 z-50 border-b-[3.5px] border-black px-4 py-3.5 flex items-center justify-between"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-2 font-black text-[1.35rem] tracking-tight",
    style: {
      fontFamily: "Archivo, sans-serif"
    }
  }, /*#__PURE__*/React.createElement("span", {
    className: "brand-box bg-[#22c55e] border-[2.5px] border-black px-2.5 py-1 shadow-[3px_3px_0_#000]"
  }, "Trex"), /*#__PURE__*/React.createElement("span", null, "Bridge")), /*#__PURE__*/React.createElement("span", {
    className: "brand-box bg-[#facc15] border-[2.5px] border-black px-2.5 py-1 text-[15px] font-black shadow-[2px_2px_0_#000]",
    style: { fontFamily: "Archivo, sans-serif", letterSpacing: "-0.3px" }
  }, "v.3")), activeTab === "home" && /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 md:grid-cols-4 gap-3 p-4"
  }, [{
    label: "Users",
    value: stats.total,
    hint: "Total accounts",
    color: "bg-[#0ea5e9]",
    icon: "group"
  }, {
    label: "Online",
    value: stats.online,
    hint: "Right now",
    color: "bg-[#eab308]",
    icon: "sensors"
  }, {
    label: "Active",
    value: stats.active,
    hint: "Enabled",
    color: "bg-[#7c3aed]",
    icon: "check_circle"
  }, {
    label: "Usage",
    value: fmtUsage(stats.usage),
    hint: "Total traffic",
    color: "bg-[#db2777]",
    icon: "database"
  }].map((k, i) => /*#__PURE__*/React.createElement("div", {
    key: k.label,
    className: "anim-in",
    style: {
      animationDelay: i * 0.06 + "s"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "lift kpi-card border-[3px] border-black shadow-[5px_5px_0_#000] p-4 relative overflow-hidden"
  }, /*#__PURE__*/React.createElement("div", {
    className: "absolute top-0 right-0 w-10 h-10 md:w-[2.9rem] md:h-[2.9rem] border-l-[2.5px] border-b-[2.5px] border-black " + k.color + " flex items-center justify-center"
  }, /*#__PURE__*/React.createElement("span", {
    className: "material-symbols-outlined kpi-ico"
  }, k.icon)), /*#__PURE__*/React.createElement("div", {
    className: "pr-12 mb-1"
  }, /*#__PURE__*/React.createElement("div", {
    className: "inline-block text-[11px] font-extrabold uppercase tracking-wide px-2.5 py-1 border-[2.5px] border-black shadow-[2px_2px_0_#000] " + k.color
  }, k.label)), /*#__PURE__*/React.createElement("div", {
    className: "text-3xl font-black tracking-tight mt-2",
    style: {
      fontFamily: "Archivo, sans-serif"
    }
  }, k.value), /*#__PURE__*/React.createElement("div", {
    className: "text-xs font-bold text-zinc-500 mt-1"
  }, k.hint))))), /*#__PURE__*/React.createElement("div", {
    className: "px-4 pb-4 anim-in",
    style: {
      animationDelay: "0.2s"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "lift kpi-card border-[3px] border-black shadow-[5px_5px_0_#000] p-4 relative overflow-hidden"
  }, /*#__PURE__*/React.createElement("div", {
    className: "absolute top-0 right-0 w-10 h-10 md:w-[2.9rem] md:h-[2.9rem] border-l-[2.5px] border-b-[2.5px] border-black bg-[#ea580c] flex items-center justify-center"
  }, /*#__PURE__*/React.createElement("span", {
    className: "material-symbols-outlined kpi-ico"
  }, "bar_chart")), /*#__PURE__*/React.createElement("div", {
    className: "pr-12 mb-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "inline-block text-[11px] font-extrabold uppercase px-2.5 py-1 border-[2.5px] border-black shadow-[2px_2px_0_#000] bg-[#ea580c]"
  }, "Requests today"), /*#__PURE__*/React.createElement("div", {
    className: "text-2xl font-black mt-1",
    style: {
      fontFamily: "Archivo, sans-serif"
    }
  }, stats.requestsToday.toLocaleString(), " ", /*#__PURE__*/React.createElement("span", {
    className: "text-base text-zinc-500"
  }, "/ ", stats.requestsLimit.toLocaleString()))), /*#__PURE__*/React.createElement("div", {
    className: "h-3 bg-zinc-200 border-2 border-black overflow-hidden"
  }, /*#__PURE__*/React.createElement("div", {
    className: "h-full bg-[#facc15]",
    style: {
      width: reqPct + "%"
    }
  })))), /*#__PURE__*/React.createElement("section", {
    className: "px-4 pb-6"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-3 mb-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex-1 h-[2.5px] bg-black"
  }), /*#__PURE__*/React.createElement(BlackStar, null), /*#__PURE__*/React.createElement("div", {
    className: "flex-1 h-[2.5px] bg-black"
  })), /*#__PURE__*/React.createElement("div", {
    className: "space-y-3"
  }, users.length === 0 && !loading ? /*#__PURE__*/React.createElement("div", {
    className: "empty-hero anim-pop"
  }, /*#__PURE__*/React.createElement("div", {
    className: "empty-marquee"
  }, /*#__PURE__*/React.createElement("div", {
    className: "empty-marquee-track"
  }, [0, 1, 2].map(function (copy) {
    return /*#__PURE__*/React.createElement("div", {
      className: "empty-marquee-group",
      key: copy
    }, ["NO USERS YET", "CREATE ONE", "QUICK OR NEW", "READY TO GO"].map(function (txt, i) {
      var isQuick = i % 2 === 0;
      return /*#__PURE__*/React.createElement(React.Fragment, {
        key: i
      }, /*#__PURE__*/React.createElement("button", {
        type: "button",
        title: isQuick ? "Quick user" : "New user",
        className: "empty-ico " + (isQuick ? "empty-ico-quick" : "empty-ico-new"),
        onClick: function (e) {
          e.preventDefault();
          e.stopPropagation();
          if (isQuick) {
            (async function () {
              try {
                var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                var r = "";
                for (var qi = 0; qi < 8; qi++) r += chars[Math.floor(Math.random() * chars.length)];
                var uname = "TrexBridge-" + r;
                showToast("Creating quick user…", "info");
                var resIp = await fetch("/api/clean-ips?operator=all&count=10&t=" + Date.now(), { credentials: "same-origin" });
                var jIp = await resIp.json().catch(function () { return {}; });
                if (!resIp.ok || !Array.isArray(jIp.ips) || !jIp.ips.length) throw new Error(jIp.error || "CleanIP failed");
                var ipsStr = jIp.ips.slice(0, 10).join(String.fromCharCode(10));
                var fragBase = { mode: "flux", packets: "tlshello", length: "5,94,1", interval: "0", maxSplit: "0", dual: true, packets2: "1-1", length2: "109,1", interval2: "1", maxSplit2: "355", protocols: "vless" };
                var res = await fetch("/api/users", {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  credentials: "same-origin",
                  body: JSON.stringify({ username: uname, limit_gb: null, expiry_days: null, ips: ipsStr, port: "443", tls: "on", fingerprint: "ios", block_ads: 1, frag_len: JSON.stringify(fragBase), frag_int: "0", ip_count: 10, ip_operator: "all", user_socks5: null, auto_rotate_user_proxy: 0 })
                });
                var j = await res.json().catch(function () { return {}; });
                if (!res.ok) throw new Error(j.error || "Create failed");
                showToast("Quick user ready", "success");
                loadUsers(false);
              } catch (err) {
                showToast(err && err.message ? err.message : "Quick failed", true);
              }
            })();
          } else {
            setActiveTab("create");
          }
        }
      }, /*#__PURE__*/React.createElement("span", {
        className: "material-symbols-outlined",
        style: { fontSize: 18 }
      }, isQuick ? "auto_awesome" : "rocket_launch")), /*#__PURE__*/React.createElement("span", {
        className: "empty-marquee-text"
      }, txt));
    }));
  })))) : null, users.map((u, i) => /*#__PURE__*/React.createElement("div", {
    key: u.id,
    className: "anim-pop",
    style: {
      animationDelay: 0.1 + i * 0.08 + "s"
    }
  }, /*#__PURE__*/React.createElement(UserCard, {
    user: u,
    onAction: msg => {
      if (typeof msg === "string" && msg.indexOf("edit:") === 0) {
        const name = msg.slice(5);
        const found = users.find(x => x.username === name);
        if (found) {
          setEditUser(found);
          setActiveTab("create");
        } else showToast("User not found", true);
        return;
      }
      showToast(msg);
    },
    onRefresh: () => loadUsers(true)
  })))))), activeTab === "create" && /*#__PURE__*/React.createElement(CreateView, {
    onToast: showToast,
    editUser: editUser,
    onClearEdit: () => setEditUser(null),
    onDone: () => {
      setEditUser(null);
      setActiveTab("home");
      loadUsers(false);
    }
  }), activeTab === "settings" && /*#__PURE__*/React.createElement(SettingsView, {
    onToast: showToast
  }), /*#__PURE__*/React.createElement("nav", {
    className: "glass-nav fixed bottom-0 left-0 right-0 z-50 border-t-[3.5px] border-black px-4 py-3.5"
  }, /*#__PURE__*/React.createElement("div", {
    className: "bottom-nav max-w-lg mx-auto flex items-stretch justify-between gap-2"
  }, [{
    id: "home",
    label: "Dashboard"
  }, {
    id: "create",
    label: "Create"
  }, {
    id: "settings",
    label: "Settings"
  }].map(n => /*#__PURE__*/React.createElement("button", {
    key: n.id,
    type: "button",
    className: "nav-item " + (activeTab === n.id ? "active" : ""),
    onClick: () => setActiveTab(n.id)
  }, /*#__PURE__*/React.createElement("span", {
    className: "nav-label"
  }, n.label))))), toast && /*#__PURE__*/React.createElement("div", {
    className: "toast"
  }, toast));
}
function UserCard({
  user,
  onAction,
  onRefresh
}) {
  const isOnline = user.last_active && Date.now() - user.last_active < 20000;
  const volPct = user.limit_gb ? Math.min(100, user.used_gb / user.limit_gb * 100) : 0;
  const reqPct = user.limit_req ? Math.min(100, user.used_req / user.limit_req * 100) : 0;
  const _ucBg = (function(){var c=["#fef08a","#bae6fd","#ddd6fe","#fbcfe8","#bbf7d0","#fed7aa","#fde68a","#e9d5ff"];var h=0;var n=String(user.username||"");for(var i=0;i<n.length;i++)h=(h*31+n.charCodeAt(i))>>>0;return c[h%c.length];})();
  return /*#__PURE__*/React.createElement("article", {
    className: "lift user-card border-[3px] border-black shadow-[5px_5px_0_#000] overflow-hidden"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center justify-between px-4 py-3 border-b-[3px] border-black",
    style: {
      background: _ucBg
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "font-black text-[15px] border-[2.5px] border-black px-2.5 py-1 shadow-[2px_2px_0_#000] inline-block",
    style: {
      fontFamily: "Archivo, sans-serif",
      background: (function(){var c=["#eab308","#0ea5e9","#7c3aed","#db2777","#16a34a","#ea580c","#ca8a04","#4f46e5"];var h=0;var n=String(user.username||"");for(var i=0;i<n.length;i++)h=(h*31+n.charCodeAt(i))>>>0;return c[h%c.length];})(),
      color: "#fff"
    }
  }, user.username), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-1.5"
  }, /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] font-extrabold px-2.5 py-1 border-2 border-black " + (user.is_active ? "bg-[#16a34a] text-white shadow-[2px_2px_0_#000]" : "bg-[#dc2626] text-white shadow-[2px_2px_0_#000]")
  }, user.is_active ? "Active" : "Off"), isOnline && /*#__PURE__*/React.createElement("span", {
    className: "text-[10px] font-extrabold px-2.5 py-1 border-2 border-black bg-[#eab308] text-black shadow-[2px_2px_0_#000]"
  }, (user.online_count || 1) + " online"))), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 gap-3 p-4 bg-[#fff7ed]"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "text-[10px] font-extrabold text-zinc-500 uppercase"
  }, "Traffic"), /*#__PURE__*/React.createElement("div", {
    className: "font-extrabold text-sm mt-0.5"
  }, fmtTraffic(user.used_gb), " / ", (user.limit_gb == null || user.limit_gb === "" ? "∞" : fmtTraffic(user.limit_gb))), /*#__PURE__*/React.createElement("div", {
    className: "h-2 bg-zinc-200 border-2 border-black mt-1.5 overflow-hidden"
  }, /*#__PURE__*/React.createElement("div", {
    className: "h-full " + (volPct >= 90 ? "bg-red-500" : "bg-[#facc15]"),
    style: {
      width: volPct + "%"
    }
  }))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "text-[10px] font-extrabold text-zinc-500 uppercase"
  }, "Requests"), /*#__PURE__*/React.createElement("div", {
    className: "font-extrabold text-sm mt-0.5"
  }, user.used_req, " / ", user.limit_req ?? "∞"), /*#__PURE__*/React.createElement("div", {
    className: "h-2 bg-zinc-200 border-2 border-black mt-1.5 overflow-hidden"
  }, /*#__PURE__*/React.createElement("div", {
    className: "h-full bg-[#db2777]",
    style: {
      width: reqPct + "%"
    }
  })))), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-4 px-4 pb-3 text-xs font-bold text-zinc-500"
  }, /*#__PURE__*/React.createElement("span", null, "Time: ", user.expiry_days == null ? "∞" : user.expiry_days + "d"), /*#__PURE__*/React.createElement("span", null, "Online: ", user.online_count, " / ", user.ip_limit ?? "∞"), /*#__PURE__*/React.createElement("span", null, "Ports: ", user.port)), /*#__PURE__*/React.createElement("div", {
    className: "flex justify-between px-4 py-3 border-t-[3px] border-black",
    style: { background: _ucBg }
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex gap-1.5"
  }, /*#__PURE__*/React.createElement(IconBtn, {
    color: "bg-[#7c3aed]",
    title: "Subscription",
    onClick: async () => {
      const ok = await copyText(location.origin + "/export/" + encodeURIComponent(user.username));
      showToast(ok ? "Subscription copied" : "Copy failed", ok ? "copy" : true);
    },
    icon: "bar_chart"
  }), /*#__PURE__*/React.createElement(IconBtn, {
    color: "bg-[#eab308]",
    title: "Config",
    white: false,
    onClick: async () => {
      try {
        const res = await fetch("/api/users/" + encodeURIComponent(user.username) + "/configs?t=" + Date.now(), {
          credentials: "same-origin"
        });
        const j = await res.json().catch(() => ({}));
        const links = j.links || [];
        if (!links.length) return onAction("No configs");
        const ok = await copyText(links.join("\\n"));
        showToast(ok ? "Config ×" + links.length : "Copy failed", ok ? "copy" : true);
      } catch (e) {
        onAction("Config failed");
      }
    },
    icon: "content_copy"
  }), /*#__PURE__*/React.createElement(IconBtn, {
    color: "bg-[#0ea5e9]",
    title: "QR",
    onClick: () => {
      const sub = location.origin + "/export/" + encodeURIComponent(user.username) + "?raw=1";
      const name = String(user.username || "").replace(/</g, "");
      const cols = ["#facc15","#7dd3fc","#a78bfa","#f9a8d4","#86efac","#fdba74","#fde68a","#c4b5fd"];
      let h = 0; for (let k = 0; k < name.length; k++) h = (h * 31 + name.charCodeAt(k)) >>> 0;
      const chipBg = cols[h % cols.length];
      const bgHex = chipBg.replace("#", "");
      const qrUrl = "https://api.qrserver.com/v1/create-qr-code/?size=320x320&margin=14&color=0a0a0a&bgcolor=" + bgHex + "&data=" + encodeURIComponent(sub);
      const wrap = document.createElement("div");
      wrap.style.cssText = "position:fixed;inset:0;z-index:9999;background:rgba(10,10,10,.55);display:flex;align-items:center;justify-content:center;padding:max(12px,3vw)";
      wrap.onclick = function (e) { if (e.target === wrap) wrap.remove(); };
      const ico = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h3v3h-3zM20 14v6M14 20h3"/></svg>';
      wrap.innerHTML = '<div style="display:flex;flex-direction:column;align-items:stretch;gap:10px;width:min(280px,78vw)">' +
        '<div style="display:flex;align-items:center;gap:8px;width:100%">' +
        '<div style="flex:1;min-width:0;display:flex;align-items:center;gap:8px;padding:8px 10px;border:2.5px solid #000;box-shadow:2px 2px 0 #000;background:' + chipBg + ';font-weight:900;font-size:13px">' +
        ico +
        '<span style="min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + name + '</span></div>' +
        '<button type="button" id="tb-qr-x" style="flex-shrink:0;width:40px;height:40px;border:2.5px solid #000;background:#ef4444;color:#fff;font-weight:900;font-size:20px;line-height:1;cursor:pointer;box-shadow:2px 2px 0 #000">×</button>' +
        '</div>' +
        '<div style="width:100%;box-sizing:border-box;padding:12px;background:' + chipBg + ';border:3px solid #000;box-shadow:4px 4px 0 #000;display:flex;justify-content:center">' +
        '<img src="' + qrUrl + '" alt="QR" style="width:100%;height:auto;display:block"/>' +
        '</div></div>';
      document.body.appendChild(wrap);
      const xBtn = document.getElementById("tb-qr-x");
      if (xBtn) xBtn.onclick = function () { wrap.remove(); };
    },
    icon: "qr_code_2"
  })), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-1.5"
  }, /*#__PURE__*/React.createElement(IconBtn, {
    color: "bg-[#c4b5fd]",
    title: "Edit",
    onClick: () => onAction("edit:" + user.username),
    icon: "edit"
  }), /*#__PURE__*/React.createElement(IconBtn, {
    color: user.is_active ? "bg-[#fb923c]" : "bg-[#ef4444]",
    title: user.is_active ? "Disable" : "Enable",
    onClick: async () => {
      try {
        const res = await fetch("/api/users/" + encodeURIComponent(user.username), {
          method: "PUT",
          headers: {
            "Content-Type": "application/json"
          },
          credentials: "same-origin",
          body: JSON.stringify({
            toggle_only: true
          })
        });
        if (res.ok) {
          showToast(user.is_active ? "User disabled" : "User enabled", user.is_active ? true : "success");
          if (typeof onRefresh === "function") onRefresh();
        } else showToast("Toggle failed", true);
      } catch (e) {
        showToast("Toggle failed", true);
      }
    },
    icon: "power_settings_new"
  }), /*#__PURE__*/React.createElement(IconBtn, {
    color: "bg-[#2dd4bf]",
    title: "Reset",
    onClick: () => {
      showConfirm("Reset traffic for " + user.username + "?", async () => {
        try {
          const res = await fetch("/api/users/" + encodeURIComponent(user.username), {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify({ reset_action: "volume" })
          });
          if (res.ok) {
            showToast("Traffic reset", "success");
            if (typeof onRefresh === "function") onRefresh();
          } else showToast("Reset failed", true);
        } catch (e) {
          showToast("Reset failed", true);
        }
      });
    },
    icon: "replay"
  }), /*#__PURE__*/React.createElement(IconBtn, {
    color: "bg-[#dc2626]",
    title: "Delete",
    onClick: () => {
      showConfirm("Delete user " + user.username + "? This cannot be undone.", async () => {
        try {
          const res = await fetch("/api/users/" + encodeURIComponent(user.username), {
            method: "DELETE",
            credentials: "same-origin"
          });
          if (res.ok) {
            onAction("Deleted");
            if (typeof onRefresh === "function") onRefresh();
          } else onAction("Delete failed");
        } catch (e) {
          onAction("Delete failed");
        }
      });
    },
    icon: "delete",
    white: true
  }))));
}
function IconBtn({
  color,
  onClick,
  icon,
  white
}) {
  return /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: onClick,
    className: "w-9 h-9 border-[2.5px] border-black shadow-[2px_2px_0_#000] flex items-center justify-center " + color + " hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[3px_3px_0_#000] active:translate-x-0.5 active:translate-y-0.5 transition-all"
  }, /*#__PURE__*/React.createElement("span", {
    className: "material-symbols-outlined",
    style: {
      fontSize: 20,
      fontVariationSettings: "'FILL' 1, 'wght' 700, 'GRAD' 0, 'opsz' 24",
      color: "#000"
    }
  }, icon));
}
const FRAG_PRESETS = {
  flux: { mode: "flux", packets: "tlshello", length: "5,94,1", interval: "0", maxSplit: "0", dual: true, packets2: "1-1", length2: "109,1", interval2: "1", maxSplit2: "355" },
  default: { mode: "default", packets: "tlshello", length: "100-200", interval: "1-1", maxSplit: "100-200" },
  trex: { mode: "flux", packets: "tlshello", length: "5,94,1", interval: "0", maxSplit: "0", dual: true, packets2: "1-1", length2: "109,1", interval2: "1", maxSplit2: "355" }
};
function InField(props) {
  var icon = props.icon;
  var rest = Object.assign({}, props);
  delete rest.icon;
  return React.createElement("div", { className: "input-wrap" },
    React.createElement("span", { className: "material-symbols-outlined in-ico" }, icon),
    React.createElement("input", Object.assign({ className: "neo-input" }, rest)));
}
function CreateView({
  onToast,
  onDone,
  editUser,
  onClearEdit
}) {
  const [tab, setTab] = useState("basic");
  const [username, setUsername] = useState("");
  const [limitGb, setLimitGb] = useState("");
  const [days, setDays] = useState("");
  const [limitReq, setLimitReq] = useState("");
  const [ipLimit, setIpLimit] = useState("");
  const [autoVol, setAutoVol] = useState("0");
  const [autoReq, setAutoReq] = useState("0");
  const [fragMode, setFragMode] = useState("flux");
  const [protoVless, setProtoVless] = useState(true);
  const [protoTrojan, setProtoTrojan] = useState(false);
  const [fingerprint, setFingerprint] = useState("ios");
  const [blockPorn, setBlockPorn] = useState(false);
  const [blockAds, setBlockAds] = useState(true);
  const [blockMalware, setBlockMalware] = useState(false);
  const [blockGambling, setBlockGambling] = useState(false);
  const [blockSocial, setBlockSocial] = useState(false);
  const [blockHosts, setBlockHosts] = useState([]);
  const [blockHostInput, setBlockHostInput] = useState("");
  const [ports, setPorts] = useState(["443", "80"]);
  const [customPorts, setCustomPorts] = useState("");
  const [ipsText, setIpsText] = useState("");
  const [customIp, setCustomIp] = useState("");
  const [ipOperator, setIpOperator] = useState("all");
  const [ipCount, setIpCount] = useState(10);
  const [operators, setOperators] = useState(OPERATORS_FALLBACK);
  const [showIpModal, setShowIpModal] = useState(false);
  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/clean-ips?operator=all&count=1&t=" + Date.now(), { credentials: "same-origin" });
        const j = await res.json().catch(() => ({}));
        if (cancelled || !res.ok || !j.operators) return;
        const keys = Object.keys(j.operators).filter(k => String(k).toLowerCase() !== "all");
        const ops = [{ key: "all", label: "All", count: j.operators.all || j.operators.All || 0 }];
        keys.forEach(k => {
          ops.push({ key: k, label: k, count: j.operators[k] || 0 });
        });
        setOperators(ops);
      } catch (e) {}
    })();
    return () => { cancelled = true; };
  }, []);
  const [exitProxy, setExitProxy] = useState("");
  const [exitCountry, setExitCountry] = useState("");
  const [exitStatus, setExitStatus] = useState("");
  const [ipLoading, setIpLoading] = useState(false);
  const [creating, setCreating] = useState(false);
  useEffect(() => {
    if (!editUser) return;
    setUsername(editUser.username || "");
    setLimitGb(editUser.limit_gb != null && editUser.limit_gb !== "" ? String(editUser.limit_gb) : "");
    setDays(editUser.expiry_days != null && editUser.expiry_days !== "" ? String(editUser.expiry_days) : "");
    setLimitReq(editUser.limit_req != null && editUser.limit_req !== "" ? String(editUser.limit_req) : "");
    setIpLimit(editUser.ip_limit != null && editUser.ip_limit !== "" ? String(editUser.ip_limit) : "");
    setAutoVol(String(editUser.auto_reset_vol_days || 0));
    setAutoReq(String(editUser.auto_reset_req_days || 0));
    setFingerprint(editUser.fingerprint || "ios");
    setBlockPorn(!!Number(editUser.block_porn));
    setBlockAds(editUser.block_ads === undefined || Number(editUser.block_ads) !== 0);
    try {
      var _fj = editUser.frag_len ? JSON.parse(String(editUser.frag_len)) : null;
      if (_fj && typeof _fj === "object") {
        setBlockMalware(!!_fj.block_malware);
        setBlockGambling(!!_fj.block_gambling);
        setBlockSocial(!!_fj.block_social);
        setBlockHosts(Array.isArray(_fj.block_hosts) ? _fj.block_hosts.map(String) : []);
      } else {
        setBlockMalware(false); setBlockGambling(false); setBlockSocial(false); setBlockHosts([]);
      }
    } catch (eL) { setBlockMalware(false); setBlockGambling(false); setBlockSocial(false); setBlockHosts([]); }
    setPorts(String(editUser.port || "443").split(",").map(function (s) { return s.trim(); }).filter(Boolean));
    setCustomPorts("");
    setIpsText(editUser.ips ? String(editUser.ips).replace(/\\r/g, "").split(/\\n/).filter(Boolean).join("\\n") : "");
    setIpOperator(editUser.ip_operator || "all");
    setIpCount(Number(editUser.ip_count) || 20);
    try {
      var _es = editUser.user_socks5 || "";
      var _ec = (editUser.user_proxy_iata || "").toString().toUpperCase();
      if (_es && String(_es).trim().charAt(0) === "[") {
        try {
          var _arr = JSON.parse(_es);
          if (Array.isArray(_arr) && _arr[0]) {
            _es = _arr[0].proxy || _arr[0].url || _es;
            if (_arr[0].country) _ec = String(_arr[0].country).toUpperCase();
          }
        } catch (eE) {}
      }
      setExitProxy(_es || "");
      setExitCountry(_ec || "");
      setExitStatus(_ec || "");
    } catch (eEx) {
      setExitProxy(editUser.user_socks5 || "");
      setExitCountry("");
      setExitStatus("");
    }
    var mode = "trex";
    try {
      var raw = editUser.frag_len ? String(editUser.frag_len) : "";
      if (raw.charAt(0) === "{") {
        var f = JSON.parse(raw);
        if (f.mode) mode = String(f.mode);
        else if (f.dual || f.packets2) mode = "trex";
        if (f.protocols) {
          var ps = String(f.protocols).split(",").map(function (x) { return x.trim().toLowerCase(); });
          setProtoVless(ps.indexOf("vless") >= 0 || !ps.length);
          setProtoTrojan(ps.indexOf("trojan") >= 0);
        }
      } else if (raw.indexOf("trex") >= 0 || raw.indexOf("packets2") >= 0) mode = "trex";
      else if (raw.indexOf("flux") >= 0) mode = "flux";
      else if (raw) mode = "default";
    } catch (e) {}
    setFragMode(mode);
    setTab("basic");
  }, [editUser]);
  const togglePort = p => setPorts(prev => prev.includes(p) ? prev.filter(x => x !== p) : [...prev, p]);
  const handleQuick = async () => {
    if (creating) return;
    setCreating(true);
    try {
      const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
      let r = "";
      for (let i = 0; i < 8; i++) r += chars[Math.floor(Math.random() * chars.length)];
      const uname = "TrexBridge-" + r;
      let ipsStr = null;
      try {
        const ctrl = typeof AbortController !== "undefined" ? new AbortController() : null;
        const timer = ctrl ? setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, 2500) : null;
        const res = await fetch("/api/clean-ips?operator=all&count=5&t=" + Date.now(), {
          credentials: "same-origin",
          signal: ctrl ? ctrl.signal : undefined
        });
        if (timer) clearTimeout(timer);
        const j = await res.json().catch(() => ({}));
        if (res.ok && Array.isArray(j.ips) && j.ips.length) {
          ipsStr = j.ips.slice(0, 5).join(String.fromCharCode(10));
        }
      } catch (e) {
        /* continue without clean IPs — faster quick create */
      }
      const fragBase = {
        mode: "flux",
        packets: "tlshello",
        length: "5,94,1",
        interval: "0",
        maxSplit: "0",
        dual: true,
        packets2: "1-1",
        length2: "109,1",
        interval2: "1",
        maxSplit2: "355",
        protocols: "vless"
      };
      const body = {
        username: uname,
        limit_gb: null,
        expiry_days: null,
        limit_req: null,
        ip_limit: null,
        ips: ipsStr,
        port: "443",
        tls: "on",
        fingerprint: "ios",
        block_porn: 0,
        block_ads: 1,
        frag_len: JSON.stringify(fragBase),
        frag_int: "0",
        auto_reset_vol_days: 0,
        auto_reset_req_days: 0,
        ip_count: 10,
        ip_operator: "all",
        user_socks5: null,
        auto_rotate_user_proxy: 0
      };
      const res = await fetch("/api/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify(body)
      });
      const j = await res.json().catch(() => ({}));
      if (!res.ok) {
        onToast(j.error || ("Quick failed " + res.status), true);
        return;
      }
      onToast("Quick user created: " + uname, "success");
      if (typeof onDone === "function") onDone();
    } catch (e) {
      onToast("Quick create failed", true);
    } finally {
      setCreating(false);
    }
  };
  const applyIps = async () => {
    setIpLoading(true);
    try {
      const res = await fetch("/api/clean-ips?operator=" + encodeURIComponent(ipOperator || "all") + "&count=" + encodeURIComponent(String(ipCount || 20)) + "&t=" + Date.now(), {
        credentials: "same-origin"
      });
      const j = await res.json().catch(() => ({}));
      if (!res.ok) {
        onToast(j.error || "IP pool failed", true);
        setIpLoading(false);
        return;
      }
      const list = j.ips || [];
      if (!list.length) {
        onToast("No IPs", true);
        setIpLoading(false);
        return;
      }
      setIpsText(list.join("\\n"));
      onToast("Loaded " + list.length + " IPs", "success");
      setShowIpModal(false);
    } catch (e) {
      onToast("IP pool failed", true);
    }
    setIpLoading(false);
  };
  const handleCreate = async () => {
    let finalName = String(username || "").trim();
    if (!finalName) return onToast("Username required", true);
    // New user: auto-prefix TrexBridge- if missing (e.g. 758 -> TrexBridge-758)
    const isEditNow = !!(editUser && editUser.username);
    if (!isEditNow && !/^TrexBridge[-_]/i.test(finalName)) {
      finalName = "TrexBridge-" + finalName;
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(finalName)) return onToast("Invalid username", true);
    const allPorts = [...ports, ...customPorts.split(/\\s+/).filter(Boolean)];
    if (!allPorts.length) return onToast("Select at least one port", true);
    if (!protoVless && !protoTrojan) return onToast("Select at least one protocol", true);
    const protos = [];
    if (protoVless) protos.push("vless");
    if (protoTrojan) protos.push("trojan");
    if (!protos.length) protos.push("vless");
    const modeSel = String(fragMode || "flux").toLowerCase();
    let fragBase;
    if (modeSel === "flux" || modeSel === "trex") {
      fragBase = {
        mode: "flux",
        packets: "tlshello",
        length: "5,94,1",
        interval: "0",
        maxSplit: "0",
        dual: true,
        packets2: "1-1",
        length2: "109,1",
        interval2: "1",
        maxSplit2: "355",
        protocols: protos.join(",")
      };
    } else {
      fragBase = {
        mode: "default",
        packets: "tlshello",
        length: "100-200",
        interval: "1-1",
        maxSplit: "100-200",
        protocols: protos.join(",")
      };
    }
    try {
      if (blockHosts && blockHosts.length) fragBase.block_hosts = blockHosts.slice();
      if (blockMalware) fragBase.block_malware = true;
      if (blockGambling) fragBase.block_gambling = true;
      if (blockSocial) fragBase.block_social = true;
    } catch (eF) {}
    setCreating(true);
    try {
      const usePorts = (ports && ports.length) ? ports : allPorts;
      const body = {
        username: finalName,
        limit_gb: limitGb !== "" ? Number(limitGb) : null,
        expiry_days: days !== "" ? Number(days) : null,
        limit_req: limitReq !== "" ? Number(limitReq) : null,
        ip_limit: ipLimit !== "" ? Number(ipLimit) : null,
        ips: ipsText.trim() || null,
        port: usePorts.join(","),
        tls: usePorts.some(p => TLS_PORTS.includes(String(p))) ? "on" : "off",
        fingerprint,
        block_porn: blockPorn ? 1 : 0,
        block_ads: blockAds ? 1 : 0,
        frag_len: JSON.stringify(fragBase),
        frag_int: String(fragBase.interval || "0"),
        auto_reset_vol_days: parseInt(autoVol, 10) || 0,
        auto_reset_req_days: parseInt(autoReq, 10) || 0,
        ip_count: ipCount || 20,
        ip_operator: ipOperator || "all",
        user_socks5: exitProxy.trim() ? (exitCountry ? JSON.stringify([{ proxy: exitProxy.trim(), country: String(exitCountry).toUpperCase() }]) : exitProxy.trim()) : null,
        user_proxy_iata: null,
        auto_rotate_user_proxy: exitProxy.trim() ? 1 : 0
      };
      const isEdit = !!(editUser && editUser.username);
      const res = await fetch(isEdit ? "/api/users/" + encodeURIComponent(editUser.username) : "/api/users", {
        method: isEdit ? "PUT" : "POST",
        headers: {
          "Content-Type": "application/json"
        },
        credentials: "same-origin",
        body: JSON.stringify(body)
      });
      const j = await res.json().catch(() => ({}));
      if (!res.ok) {
        onToast(j.error || ((isEdit ? "Update failed " : "Create failed ") + res.status), true);
        return;
      }
      onToast((isEdit ? "Updated " : "Created ") + finalName, "success");
      if (typeof onClearEdit === "function") onClearEdit();
      if (typeof onDone === "function") onDone();
    } catch (e) {
      onToast("Save failed", true);
    } finally {
      setCreating(false);
    }
  };
  const Chip = ({
    active,
    onClick,
    children,
    color
  }) => /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: onClick,
    className: "min-h-[42px] w-full border-[2.5px] border-black font-extrabold text-sm transition-all flex items-center justify-center gap-1 relative overflow-hidden " + (active ? "bg-[#facc15] text-black shadow-[3px_3px_0_#000] -translate-x-px -translate-y-px chip-on-shine" : (color || "bg-white") + " text-white shadow-[2px_2px_0_#000]")
  }, children);
  const StarDiv = () => /*#__PURE__*/React.createElement("div", {
    className: "divider-star",
    "aria-hidden": "true"
  }, /*#__PURE__*/React.createElement("div", {
    className: "line"
  }), /*#__PURE__*/React.createElement(BlackStar, {
    size: 14
  }), /*#__PURE__*/React.createElement("div", {
    className: "line"
  }));
  const Head = ({
    icon,
    iconBg,
    barBg,
    title,
    sub,
    right
  }) => /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-3 px-4 py-3.5 border-b-[3px] border-black " + barBg
  }, /*#__PURE__*/React.createElement("div", {
    className: "w-10 h-10 border-[2.5px] border-black flex items-center justify-center shrink-0 shadow-[2px_2px_0_#000] " + iconBg
  }, /*#__PURE__*/React.createElement("span", {
    className: "material-symbols-outlined",
    style: {
      fontSize: 20
    }
  }, icon)), /*#__PURE__*/React.createElement("div", {
    className: "min-w-0 flex-1"
  }, /*#__PURE__*/React.createElement("div", {
    className: "font-black text-[15px] leading-tight",
    style: {
      fontFamily: "Archivo, sans-serif"
    }
  }, title), /*#__PURE__*/React.createElement("div", {
    className: "text-[11px] font-bold text-black/55 mt-0.5"
  }, sub)), right);
  return /*#__PURE__*/React.createElement("div", {
    className: "px-4 pt-5 pb-8 max-w-lg mx-auto"
  }, /*#__PURE__*/React.createElement("div", {
    className: "anim-in flex items-start justify-between gap-3 mb-4"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center gap-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "w-11 h-11 border-[2.5px] border-black shadow-[3px_3px_0_#000] flex items-center justify-center " + (editUser ? "bg-[#c4b5fd]" : "bg-[#fb923c]")
  }, /*#__PURE__*/React.createElement("span", {
    className: "material-symbols-outlined",
    style: { fontSize: 22 }
  }, editUser ? "edit" : "person_add")), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    className: "text-2xl font-black tracking-tight leading-none",
    style: {
      fontFamily: "Archivo, sans-serif"
    }
  }, editUser ? "Edit User" : "New User"), /*#__PURE__*/React.createElement("p", {
    className: "text-sm font-bold text-zinc-500 mt-1"
  }, editUser ? ("Editing · " + (editUser.username || "")) : "Create a new account"))), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 shrink-0"
  }, /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: handleQuick,
    title: "Quick user",
    className: "lift w-11 h-11 flex items-center justify-center bg-[#fb923c] border-[2.5px] border-black shadow-[3px_3px_0_#000]"
  }, /*#__PURE__*/React.createElement("span", {
    className: "material-symbols-outlined",
    style: {
      fontSize: 22
    }
  }, "auto_awesome")), /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: handleCreate,
    title: "New user",
    className: "lift w-11 h-11 flex items-center justify-center bg-[#a78bfa] border-[2.5px] border-black shadow-[3px_3px_0_#000]"
  }, /*#__PURE__*/React.createElement("span", {
    className: "material-symbols-outlined",
    style: {
      fontSize: 22
    }
  }, "rocket_launch")))), /*#__PURE__*/React.createElement("div", {
    className: "anim-in nb-tabs",
    style: {
      animationDelay: "0.04s"
    }
  }, [{
    id: "basic",
    label: "Basic",
    icon: "badge"
  }, {
    id: "security",
    label: "Security",
    icon: "shield"
  }, {
    id: "network",
    label: "Network",
    icon: "public"
  }].map(t => /*#__PURE__*/React.createElement("button", {
    key: t.id,
    type: "button",
    className: (tab === t.id ? "on tab-" + t.id : "tab-" + t.id),
    onClick: () => setTab(t.id)
  }, /*#__PURE__*/React.createElement("span", {
    className: "material-symbols-outlined"
  }, t.icon), t.label))), tab === "basic" && /*#__PURE__*/React.createElement("div", {
    className: "anim-pop"
  }, /*#__PURE__*/React.createElement("div", {
    className: "nb-card"
  }, /*#__PURE__*/React.createElement(Head, {
    icon: "badge",
    iconBg: "bg-[#ea580c]",
    barBg: "bg-[#fb923c]",
    title: "Identity",
    sub: "Username and account limits"
  }), /*#__PURE__*/React.createElement("div", {
    className: "nb-card-b space-y-4"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "field-label fl-c-yellow"
  }, "Username"), /*#__PURE__*/React.createElement(InField, {
    icon: "person",
    placeholder: "TrexBridge",
    value: username,
    onChange: e => setUsername(e.target.value)
  })), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 gap-3"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "field-label fl-c-blue"
  }, "Traffic (GB)"), /*#__PURE__*/React.createElement(InField, {
    icon: "database",
    type: "number",
    min: "0",
    placeholder: "Unlimited",
    value: limitGb,
    onChange: e => setLimitGb(e.target.value)
  }), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 mt-2"
  }, [10, 30, 50].map((n, idx) => /*#__PURE__*/React.createElement("button", {
    key: n,
    type: "button",
    onClick: () => setLimitGb(String(n)),
    className: "chip-pick " + (limitGb === String(n) ? "chip-pick-on" : ""),
    style: { background: limitGb === String(n) ? "#facc15" : ["#ef4444", "#16a34a", "#ea580c"][idx], color: limitGb === String(n) ? "#000" : "#fff" }
  }, n)))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "field-label fl-c-purple"
  }, "Days"), /*#__PURE__*/React.createElement(InField, {
    icon: "calendar_month",
    type: "number",
    min: "0",
    placeholder: "Unlimited",
    value: days,
    onChange: e => setDays(e.target.value)
  }), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 mt-2"
  }, [1, 7, 30].map((n, idx) => /*#__PURE__*/React.createElement("button", {
    key: n,
    type: "button",
    onClick: () => setDays(String(n)),
    className: "chip-pick " + (days === String(n) ? "chip-pick-on" : ""),
    style: { background: days === String(n) ? "#facc15" : ["#2563eb", "#7c3aed", "#db2777"][idx], color: days === String(n) ? "#000" : "#fff" }
  }, n))))), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 gap-3"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "field-label fl-c-red"
  }, "Request cap"), /*#__PURE__*/React.createElement(InField, {
    icon: "speed",
    type: "number",
    min: "0",
    placeholder: "Unlimited",
    value: limitReq,
    onChange: e => setLimitReq(e.target.value)
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "field-label fl-c-green"
  }, "IP limit"), /*#__PURE__*/React.createElement(InField, {
    icon: "devices",
    type: "number",
    min: "0",
    placeholder: "Unlimited",
    value: ipLimit,
    onChange: e => setIpLimit(e.target.value)
  }))))), /*#__PURE__*/React.createElement(StarDiv, null), /*#__PURE__*/React.createElement("div", {
    className: "nb-card"
  }, /*#__PURE__*/React.createElement(Head, {
    icon: "sync",
    iconBg: "bg-[#4f46e5]",
    barBg: "bg-[#818cf8]",
    title: "Auto renew",
    sub: "Reset traffic / requests on a cycle"
  }), /*#__PURE__*/React.createElement("div", {
    className: "nb-card-b grid grid-cols-2 gap-3"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "field-label fl-c-orange"
  }, "Traffic reset every N days"), /*#__PURE__*/React.createElement(InField, {
    icon: "restart_alt",
    type: "number",
    min: "0",
    placeholder: "0 = off",
    value: autoVol,
    onChange: e => setAutoVol(e.target.value)
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "field-label fl-c-pink"
  }, "Request reset every N days"), /*#__PURE__*/React.createElement(InField, {
    icon: "restart_alt",
    type: "number",
    min: "0",
    placeholder: "0 = off",
    value: autoReq,
    onChange: e => setAutoReq(e.target.value)
  }))))), tab === "security" && /*#__PURE__*/React.createElement("div", {
    className: "anim-pop"
  }, /*#__PURE__*/React.createElement("div", {
    className: "nb-card"
  }, /*#__PURE__*/React.createElement(Head, {
    icon: "tune",
    iconBg: "bg-[#ca8a04]",
    barBg: "bg-[#eab308]",
    title: "Xray Fragment",
    sub: "Mode and protocols"
  }), /*#__PURE__*/React.createElement("div", {
    className: "nb-card-b space-y-4"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "field-label fl-c-yellow"
  }, "Mode"), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 gap-2"
  }, /*#__PURE__*/React.createElement(Chip, {
    active: fragMode === "default",
    onClick: () => setFragMode("default"),
    color: "bg-[#2563eb]"
  }, /*#__PURE__*/React.createElement("span", {
    className: "material-symbols-outlined",
    style: {
      fontSize: 18
    }
  }, "settings"), " Default"), /*#__PURE__*/React.createElement(Chip, {
    active: fragMode === "flux",
    onClick: () => setFragMode("flux"),
    color: "bg-[#ea580c]"
  }, /*#__PURE__*/React.createElement("span", {
    className: "material-symbols-outlined",
    style: {
      fontSize: 18
    }
  }, "bolt"), " Flux"))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "field-label fl-c-blue"
  }, "Protocols"), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 gap-2"
  }, /*#__PURE__*/React.createElement(Chip, {
    active: protoVless,
    onClick: () => {
      if (protoVless && !protoTrojan) return onToast("Select at least one protocol", true);
      setProtoVless(!protoVless);
    },
    color: "bg-[#2563eb]"
  }, /*#__PURE__*/React.createElement("span", {
    className: "material-symbols-outlined",
    style: {
      fontSize: 18
    }
  }, "bolt"), " VLESS"), /*#__PURE__*/React.createElement(Chip, {
    active: protoTrojan,
    onClick: () => {
      if (protoTrojan && !protoVless) return onToast("Select at least one protocol", true);
      setProtoTrojan(!protoTrojan);
    },
    color: "bg-[#dc2626]"
  }, /*#__PURE__*/React.createElement("span", {
    className: "material-symbols-outlined",
    style: {
      fontSize: 18
    }
  }, "encrypted"), " Trojan"))))), /*#__PURE__*/React.createElement(StarDiv, null), /*#__PURE__*/React.createElement("div", {
    className: "nb-card"
  }, /*#__PURE__*/React.createElement(Head, {
    icon: "fingerprint",
    iconBg: "bg-[#7c3aed]",
    barBg: "bg-[#a78bfa]",
    title: "TLS Fingerprint",
    sub: "Client hello fingerprint"
  }), /*#__PURE__*/React.createElement("div", {
    className: "nb-card-b"
  }, /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 gap-2"
  }, FINGERPRINTS.map((fp, fi) => /*#__PURE__*/React.createElement(Chip, {
    key: fp,
    active: fingerprint === fp,
    onClick: () => setFingerprint(fp),
    color: ["bg-[#2563eb]", "bg-[#ea580c]", "bg-[#16a34a]", "bg-[#db2777]", "bg-[#4f46e5]", "bg-[#dc2626]", "bg-[#0891b2]", "bg-[#7c3aed]", "bg-[#0d9488]", "bg-[#e11d48]"][fi % 10]
  }, fp.charAt(0).toUpperCase() + fp.slice(1)))))), /*#__PURE__*/React.createElement(StarDiv, null), /*#__PURE__*/React.createElement("div", {
    className: "nb-card"
  }, /*#__PURE__*/React.createElement(Head, {
    icon: "shield",
    iconBg: "bg-[#db2777]",
    barBg: "bg-[#f472b6]",
    title: "Filters",
    sub: "Content blocking"
  }), /*#__PURE__*/React.createElement("div", {
    className: "nb-card-b space-y-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 gap-2"
  }, [
    { key: "nsfw", label: "NSFW", icon: "block", active: blockPorn, toggle: function(){ setBlockPorn(!blockPorn); }, color: "bg-[#dc2626]" },
    { key: "ads", label: "Ads", icon: "ads_click", active: blockAds, toggle: function(){ setBlockAds(!blockAds); }, color: "bg-[#2563eb]" },
    { key: "malware", label: "Malware", icon: "security", active: blockMalware, toggle: function(){ setBlockMalware(!blockMalware); }, color: "bg-[#ea580c]" },
    { key: "gambling", label: "Gambling", icon: "casino", active: blockGambling, toggle: function(){ setBlockGambling(!blockGambling); }, color: "bg-[#7c3aed]" },
    { key: "social", label: "Social", icon: "groups", active: blockSocial, toggle: function(){ setBlockSocial(!blockSocial); }, color: "bg-[#db2777]" },
    { key: "trackers", label: "Trackers", icon: "visibility_off", active: blockAds, toggle: function(){ setBlockAds(!blockAds); }, color: "bg-[#0891b2]" }
  ].map(function (f) {
    return /*#__PURE__*/React.createElement("button", {
      key: f.key,
      type: "button",
      onClick: f.toggle,
      className: "min-h-[48px] border-[2.5px] border-black font-extrabold text-sm flex items-center justify-center gap-1.5 relative overflow-hidden " + (f.active ? "bg-[#facc15] text-black shadow-[3px_3px_0_#000] chip-on-shine" : f.color + " text-white shadow-[2px_2px_0_#000]")
    }, /*#__PURE__*/React.createElement("span", {
      className: "material-symbols-outlined",
      style: { fontSize: 18, color: f.active ? "#000" : "#fff" }
    }, f.icon), f.label);
  })), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "field-label fl-c-red"
  }, "Custom domains"), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 items-stretch"
  }, /*#__PURE__*/React.createElement("input", {
    className: "neo-input flex-1",
    placeholder: "example.com",
    value: blockHostInput,
    onChange: function (e) { setBlockHostInput(e.target.value); },
    onKeyDown: function (e) {
      if (e.key === "Enter") {
        e.preventDefault();
        var v = String(blockHostInput || "").trim().toLowerCase();
        if (v.indexOf("https://") === 0) v = v.slice(8);
        else if (v.indexOf("http://") === 0) v = v.slice(7);
        var _sl = v.indexOf("/");
        if (_sl >= 0) v = v.slice(0, _sl);
        if (v.indexOf("www.") === 0) v = v.slice(4);
        if (!v || v.indexOf(".") < 0) return onToast("Invalid domain", true);
        if (blockHosts.indexOf(v) >= 0) return onToast("Already added", true);
        setBlockHosts(blockHosts.concat([v]));
        setBlockHostInput("");
      }
    }
  }), /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: function () {
      var v = String(blockHostInput || "").trim().toLowerCase();
        if (v.indexOf("https://") === 0) v = v.slice(8);
        else if (v.indexOf("http://") === 0) v = v.slice(7);
        var _sl = v.indexOf("/");
        if (_sl >= 0) v = v.slice(0, _sl);
        if (v.indexOf("www.") === 0) v = v.slice(4);
      if (!v || v.indexOf(".") < 0) return onToast("Invalid domain", true);
      if (blockHosts.indexOf(v) >= 0) return onToast("Already added", true);
      setBlockHosts(blockHosts.concat([v]));
      setBlockHostInput("");
    },
    className: "h-[48px] min-h-[48px] px-5 border-[2.5px] border-black bg-[#dc2626] text-white font-extrabold text-sm shadow-[3px_3px_0_#000] shrink-0 flex items-center"
  }, "Add")), /*#__PURE__*/React.createElement("div", {
    className: "flex flex-wrap gap-2 mt-2"
  }, blockHosts.map(function (h) {
    return /*#__PURE__*/React.createElement("button", {
      key: h,
      type: "button",
      onClick: function () { setBlockHosts(blockHosts.filter(function (x) { return x !== h; })); },
      className: "inline-flex items-center justify-center gap-1 min-w-[4.5rem] h-9 px-2 border-[2.5px] border-black font-extrabold text-xs text-white shadow-[2px_2px_0_#000]",
      style: (function(){var c=["#dc2626","#ea580c","#db2777","#7c3aed","#2563eb","#16a34a","#0891b2","#ca8a04","#e11d48","#4f46e5"];var hh=0;var t=String(h);for(var i=0;i<t.length;i++)hh=(hh*31+t.charCodeAt(i))>>>0;return {background:c[hh%c.length]};})()
    }, h, /*#__PURE__*/React.createElement("span", {
      className: "material-symbols-outlined shrink-0",
      style: { fontSize: 14, color: "#fff" }
    }, "close"));
  })))))), tab === "network" && /*#__PURE__*/React.createElement("div", {
    className: "anim-pop"
  }, /*#__PURE__*/React.createElement("div", {
    className: "nb-card"
  }, /*#__PURE__*/React.createElement(Head, {
    icon: "lock",
    iconBg: "bg-[#d97706]",
    barBg: "bg-[#f59e0b]",
    title: "TLS ports",
    sub: "Encrypted entry ports"
  }), /*#__PURE__*/React.createElement("div", {
    className: "nb-card-b"
  }, /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-3 gap-2"
  }, TLS_PORTS.map((pt, ti) => /*#__PURE__*/React.createElement(Chip, {
    key: pt,
    active: ports.includes(pt),
    onClick: () => togglePort(pt),
    color: ["bg-[#dc2626]", "bg-[#ea580c]", "bg-[#db2777]", "bg-[#7c3aed]", "bg-[#2563eb]", "bg-[#0d9488]"][ti % 6]
  }, /*#__PURE__*/React.createElement("span", {
    className: "material-symbols-outlined",
    style: {
      fontSize: 14
    }
  }, "lock"), " ", pt))))), /*#__PURE__*/React.createElement(StarDiv, null), /*#__PURE__*/React.createElement("div", {
    className: "nb-card"
  }, /*#__PURE__*/React.createElement(Head, {
    icon: "cable",
    iconBg: "bg-[#0284c7]",
    barBg: "bg-[#38bdf8]",
    title: "Non-TLS ports",
    sub: "Plain WebSocket ports"
  }), /*#__PURE__*/React.createElement("div", {
    className: "nb-card-b space-y-3"
  }, /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-3 gap-2"
  }, NONTLS_PORTS.map((pt, ti) => /*#__PURE__*/React.createElement(Chip, {
    key: pt,
    active: ports.includes(pt),
    onClick: () => togglePort(pt),
    color: ["bg-[#0891b2]", "bg-[#16a34a]", "bg-[#4f46e5]", "bg-[#e11d48]", "bg-[#0284c7]", "bg-[#7c3aed]"][ti % 6]
  }, /*#__PURE__*/React.createElement("span", {
    className: "material-symbols-outlined",
    style: {
      fontSize: 14
    }
  }, "cable"), " ", pt))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "field-label"
  }, "Custom ports"), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 items-center"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex-1"
  }, /*#__PURE__*/React.createElement(InField, {
    icon: "tag",
    placeholder: "e.g. 8443",
    value: customPorts,
    onChange: e => setCustomPorts(e.target.value)
  })), /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: () => {
      const parts = String(customPorts || "").split(/[ ,]+/).map(s => s.trim()).filter(Boolean);
      if (!parts.length) return onToast("Enter a port", true);
      const next = ports.slice();
      let added = 0;
      parts.forEach(p => {
        if (!/^[0-9]{1,5}$/.test(p)) return;
        const n = parseInt(p, 10);
        if (n < 1 || n > 65535) return;
        if (next.indexOf(p) === -1) { next.push(p); added++; }
      });
      if (!added) return onToast("Invalid or duplicate port", true);
      setPorts(next);
      setCustomPorts("");
      onToast(added + " port(s) added", "success");
    },
    className: "h-[48px] min-h-[48px] px-5 border-[2.5px] border-black bg-[#16a34a] text-white font-extrabold text-sm shadow-[3px_3px_0_#000] shrink-0 self-stretch flex items-center"
  }, "Add")), /*#__PURE__*/React.createElement("div", {
    className: "flex flex-wrap gap-2 mt-2"
  }, ports.filter(function (pt) {
    return ["443", "80", "8080", "2053", "2083", "2087", "2096", "8443", "8880", "2052", "2086", "2095"].indexOf(String(pt)) < 0;
  }).map(function (pt) {
    return /*#__PURE__*/React.createElement("button", {
      key: "cport-" + pt,
      type: "button",
      onClick: function () {
        setPorts(function (prev) { return prev.filter(function (x) { return x !== pt; }); });
      },
      className: "inline-flex items-center justify-center gap-1 min-w-[4.5rem] h-9 px-2 border-[2.5px] border-black font-extrabold text-xs shadow-[2px_2px_0_#000]",
      style: (function(){var c=["#dc2626","#ea580c","#db2777","#7c3aed","#2563eb","#16a34a","#0891b2","#ca8a04","#e11d48","#4f46e5"];var h=0;var t=String(pt);for(var i=0;i<t.length;i++)h=(h*31+t.charCodeAt(i))>>>0;return {background:c[h%c.length]};})()
    }, String(pt), /*#__PURE__*/React.createElement("span", {
      className: "material-symbols-outlined shrink-0",
      style: { fontSize: 14 }
    }, "close"));
  }))))), /*#__PURE__*/React.createElement(StarDiv, null), /*#__PURE__*/React.createElement("div", {
    className: "nb-card"
  }, /*#__PURE__*/React.createElement(Head, {
    icon: "public",
    iconBg: "bg-[#db2777]",
    barBg: "bg-[#f472b6]",
    title: "Exit location",
    sub: "Optional proxy exit"
  }), /*#__PURE__*/React.createElement("div", {
    className: "nb-card-b space-y-3"
  }, /*#__PURE__*/React.createElement(InField, {
    icon: "vpn_key",
    placeholder: "socks5://host:port",
    value: exitProxy,
    onChange: e => {
      setExitProxy(e.target.value);
      setExitStatus("");
    }
  }), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2"
  }, /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: async () => {
      if (!exitProxy) return onToast("No proxy", true);
      try {
        const res = await fetch("/api/test-proxy", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({ proxy: exitProxy })
        });
        const j = await res.json().catch(() => ({}));
        const ms = j.ms != null ? j.ms : j.ping;
        const loc = (j.loc || j.countryName || j.country || j.countryCode || "").toString();
        if (res.ok && j.ok !== false && j.success !== false) {
          setExitStatus((ms != null ? ms + " ms" : "") + (loc ? (ms != null ? " · " : "") + loc : ""));
          onToast((ms != null ? ms + " ms" : "ok") + (loc ? " · " + loc : ""), "ping");
        } else {
          setExitStatus("");
          onToast(j.error || "Ping failed", true);
        }
      } catch (e) {
        onToast("Ping failed", true);
      }
    },
    className: "chip-pick flex-1",
    style: { background: "#7dd3fc", color: "#000" }
  }, "Test"), /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: () => {
      if (!exitProxy.trim()) {
        setExitProxy("");
        setExitStatus("");
        onToast("Cleared");
        return;
      }
      onToast("Applied", "success");
    },
    className: "chip-pick flex-1",
    style: { background: "#facc15", color: "#000" }
  }, "Apply"), /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: async () => {
      window.__tbRandSeq = (window.__tbRandSeq || 0) + 1;
      const mySeq = window.__tbRandSeq;
      onToast("Picking…", "ping");
      try {
        const res = await fetch("/api/random-proxy?t=" + Date.now() + "&r=" + Math.random().toString(36).slice(2), { credentials: "same-origin", cache: "no-store" });
        if (mySeq !== window.__tbRandSeq) return;
        const j = await res.json().catch(() => ({}));
        if (mySeq !== window.__tbRandSeq) return;
        let proxyVal = null;
        if (j && j.proxy) {
          proxyVal = typeof j.proxy === "string" ? j.proxy : (j.proxy.proxy || j.proxy.url || null);
        }
        if (!res.ok) {
          if (mySeq === window.__tbRandSeq) onToast((j && (j.error || j.detail)) || "Random failed", true);
          return;
        }
        if (!proxyVal || j.live === false) {
          if (mySeq === window.__tbRandSeq) onToast((j && (j.error || j.detail)) || "Offline — next", true);
          return;
        }
        setExitProxy(proxyVal);
        const ms = j.ms != null ? j.ms : null;
        const loc = (j.country || "").toString().toUpperCase();
        setExitCountry(loc || "");
        setExitStatus((ms != null ? ms + " ms" : "") + (loc ? (ms != null ? " · " : "") + loc : ""));
        if (mySeq === window.__tbRandSeq) {
          onToast((ms != null ? ms + " ms" : "OK") + (loc ? " · " + loc : ""), "ping");
        }
      } catch (e) {
        if (mySeq === window.__tbRandSeq) onToast("Random failed — try again", true);
      }
    },
    className: "chip-pick flex-1",
    style: { background: "#a78bfa", color: "#000" }
  }, "Random")))), /*#__PURE__*/React.createElement(StarDiv, null), /*#__PURE__*/React.createElement("div", {
    className: "nb-card"
  }, /*#__PURE__*/React.createElement(Head, {
    icon: "dns",
    iconBg: "bg-[#ca8a04]",
    barBg: "bg-[#eab308]",
    title: "Clean IPs",
    sub: "One IP or domain per line",
    right: /*#__PURE__*/React.createElement("button", {
      type: "button",
      onClick: async () => {
        setShowIpModal(true);
        try {
          const res = await fetch("/api/clean-ips?operator=all&count=1&t=" + Date.now(), {
            credentials: "same-origin"
          });
          const j = await res.json().catch(() => ({}));
          if (res.ok && j.operators) {
            const counts = j.operators;
            const known = { all: "All", IRANCELL: "Irancell", RIGHTEL: "Rightel", SHATEL: "Shatel", MCI: "MCI", TELECOM: "Telecom", APTEL: "Aptel", SAMANTEL: "SamanTel", PISHGAMAN: "Pishgaman", FIBER: "Fiber", ASIATECH: "Asiatech" };
            Object.keys(counts).forEach(k => {
              let op = OPERATORS.find(o => String(o.key).toLowerCase() === String(k).toLowerCase());
              if (op) op.count = counts[k];
              else if (k !== "all" && k !== "ALL") OPERATORS.push({ key: k, label: known[k] || k, count: counts[k] });
            });
            if (counts.all != null) OPERATORS[0].count = counts.all;
          }
        } catch (e) {}
      },
      className: "text-xs font-extrabold px-3 py-1.5 border-[2.5px] border-black bg-[#f9a8d4] shadow-[2px_2px_0_#000]"
    }, "IP pool")
  }), /*#__PURE__*/React.createElement("div", {
    className: "nb-card-b"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2 items-center"
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex-1"
  }, /*#__PURE__*/React.createElement(InField, {
    icon: "dns",
    placeholder: "Add IP / host",
    value: customIp,
    onChange: e => setCustomIp(e.target.value)
  })), /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: () => {
      const nl = String.fromCharCode(10);
      const parts = String(customIp || "").split(/[ ,]+/).map(s => s.trim()).filter(Boolean);
      if (!parts.length) return onToast("Enter an IP", true);
      const cur = String(ipsText || "").split(nl).map(s => s.trim()).filter(Boolean);
      let added = 0;
      parts.forEach(p => {
        if (cur.indexOf(p) === -1) {
          cur.push(p);
          added++;
        }
      });
      if (!added) return onToast("Duplicate IP", true);
      setIpsText(cur.join(nl));
      setCustomIp("");
      onToast(added + " IP added", "success");
    },
    className: "h-[48px] min-h-[48px] px-5 border-[2.5px] border-black bg-[#0891b2] text-white font-extrabold text-sm shadow-[3px_3px_0_#000] shrink-0 flex items-center"
  }, "Add")), /*#__PURE__*/React.createElement("div", {
    className: "flex flex-wrap gap-2 mt-2"
  }, String(ipsText || "").split(String.fromCharCode(10)).map(s => s.trim()).filter(Boolean).map(ip => /*#__PURE__*/React.createElement("button", {
    key: ip,
    type: "button",
    title: ip,
    onClick: () => {
      const nl = String.fromCharCode(10);
      const next = String(ipsText || "").split(nl).map(s => s.trim()).filter(Boolean).filter(x => x !== ip);
      setIpsText(next.join(nl));
    },
    className: "inline-flex items-center justify-center gap-1 min-w-[7.5rem] h-9 px-2 border-[2.5px] border-black font-extrabold text-xs shadow-[2px_2px_0_#000]",
    style: (function(){var c=["#dc2626","#ea580c","#db2777","#7c3aed","#2563eb","#16a34a","#0891b2","#ca8a04","#e11d48","#4f46e5"];var h=0;var t=String(ip);for(var i=0;i<t.length;i++)h=(h*31+t.charCodeAt(i))>>>0;return {background:c[h%c.length]};})()
  }, /*#__PURE__*/React.createElement("span", {
    className: "truncate max-w-[5.5rem]"
  }, ip), /*#__PURE__*/React.createElement("span", {
    className: "material-symbols-outlined shrink-0",
    style: {
      fontSize: 14
    }
  }, "close"))))))), showIpModal && /*#__PURE__*/React.createElement("div", {
    className: "fixed inset-0 z-[100] flex items-end sm:items-center justify-center p-4",
    style: {
      background: "rgba(0,0,0,0.4)"
    },
    onClick: () => setShowIpModal(false)
  }, /*#__PURE__*/React.createElement("div", {
    className: "w-full max-w-md bg-[#fffdf5] border-[3px] border-black shadow-[8px_8px_0_#000] anim-pop overflow-hidden",
    onClick: e => e.stopPropagation()
  }, /*#__PURE__*/React.createElement("div", {
    className: "flex items-center justify-between px-4 py-3 bg-[#facc15] border-b-[3px] border-black"
  }, /*#__PURE__*/React.createElement("div", {
    className: "font-black text-[15px]",
    style: {
      fontFamily: "Archivo, sans-serif"
    }
  }, "Clean IP pool"), /*#__PURE__*/React.createElement("button", {
    type: "button",
    onClick: () => setShowIpModal(false),
    className: "w-8 h-8 border-2 border-black bg-black text-white font-black"
  }, "×")), /*#__PURE__*/React.createElement("div", {
    className: "p-4 space-y-4 max-h-[60vh] overflow-y-auto"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "field-label"
  }, "Operator"), /*#__PURE__*/React.createElement("div", {
    className: "grid grid-cols-2 gap-2"
  }, operators.map((op, idx) => {
    const keyU = String(op.key || "").toUpperCase();
    const isWide = keyU === "ASIATECH";
    const palette = ["bg-[#2563eb]","bg-[#7c3aed]","bg-[#db2777]","bg-[#ea580c]","bg-[#16a34a]","bg-[#0891b2]","bg-[#c026d3]","bg-[#dc2626]","bg-[#ca8a04]","bg-[#4f46e5]","bg-[#0d9488]"];
    const color = keyU === "ALL" ? "bg-[#52525b]" : palette[idx % palette.length];
    const active = ipOperator === op.key;
    return /*#__PURE__*/React.createElement("button", {
      key: op.key,
      type: "button",
      onClick: () => setIpOperator(op.key),
      className: (isWide ? "col-span-2 min-h-[56px] " : "min-h-[48px] ") + "border-[2.5px] border-black font-extrabold text-sm flex flex-col items-center justify-center relative overflow-hidden " + (active ? "bg-[#facc15] text-black shadow-[4px_4px_0_#000] chip-on-shine" : color + " text-white shadow-[2px_2px_0_#000]")
    }, /*#__PURE__*/React.createElement("span", null, op.label), /*#__PURE__*/React.createElement("span", {
      className: "text-[10px] " + (active ? "opacity-80" : "opacity-90")
    }, op.count, " IPs"));
  }))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("label", {
    className: "field-label"
  }, "Count"), /*#__PURE__*/React.createElement("div", {
    className: "flex gap-2"
  }, [5, 10, 15, 20].map((n, idx) => /*#__PURE__*/React.createElement("button", {
    key: n,
    type: "button",
    onClick: () => setIpCount(n),
    className: "chip-pick " + (ipCount === n ? "chip-pick-on" : ""),
    style: { background: ipCount === n ? "#facc15" : ["#dc2626", "#16a34a", "#ea580c", "#7c3aed"][idx], color: ipCount === n ? "#000" : "#fff" }
  }, n)))), /*#__PURE__*/React.createElement("button", {
    type: "button",
    disabled: ipLoading,
    onClick: applyIps,
    className: "w-full min-h-[48px] bg-[#7c3aed] text-white border-[2.5px] border-black shadow-[4px_4px_0_#000] font-black text-sm disabled:opacity-60"
  }, ipLoading ? "Loading…" : "Apply IPs")))));
}
function SettingsView({
  onToast
}) {
  const [tab, setTab] = useState("account");
  const [updating, setUpdating] = useState(false);
  return React.createElement("div", {
    className: "px-4 py-5 max-w-lg mx-auto"
  }, React.createElement("div", {
    className: "anim-in mb-4 flex items-center gap-3"
  }, React.createElement("div", {
    className: "w-11 h-11 bg-[#a78bfa] border-[2.5px] border-black shadow-[3px_3px_0_#000] flex items-center justify-center"
  }, React.createElement("span", {
    className: "material-symbols-outlined",
    style: { fontSize: 22 }
  }, "settings")), React.createElement("div", null, React.createElement("h1", {
    className: "text-2xl font-black tracking-tight leading-none",
    style: { fontFamily: "Archivo, sans-serif" }
  }, "Settings"), React.createElement("p", {
    className: "text-sm font-bold text-zinc-500 mt-1"
  }, "Account · system · update"))), React.createElement("div", {
    className: "anim-in nb-tabs",
    style: { animationDelay: "0.04s" }
  }, [
    { id: "account", label: "Account", icon: "person" },
    { id: "system", label: "System", icon: "dns" },
    { id: "update", label: "Update", icon: "rocket_launch" }
  ].map(function (t) {
    return React.createElement("button", {
      key: t.id,
      type: "button",
      className: tab === t.id ? "on tab-" + t.id : "tab-" + t.id,
      onClick: function () { setTab(t.id); }
    }, React.createElement("span", { className: "material-symbols-outlined" }, t.icon), React.createElement("span", null, t.label));
  })), tab === "account" && React.createElement("div", {
    className: "anim-pop"
  }, React.createElement("div", {
    className: "nb-card"
  }, React.createElement("div", {
    className: "nb-card-h flex items-center gap-3",
    style: { background: "#f9a8d4" }
  }, React.createElement("div", {
    className: "w-9 h-9 bg-[#ec4899] border-[2.5px] border-black flex items-center justify-center shrink-0 shadow-[2px_2px_0_#000]"
  }, React.createElement("span", {
    className: "material-symbols-outlined",
    style: { fontSize: 18, color: "#000" }
  }, "lock")), React.createElement("div", null, React.createElement("div", {
    className: "t",
    style: { color: "#000" }
  }, "Session"), React.createElement("div", { className: "d" }, "Password & logout"))), React.createElement("div", {
    className: "nb-card-b space-y-3"
  }, React.createElement("div", null, React.createElement("label", {
    className: "field-label fl-c-red"
  }, "Current password"), React.createElement("input", {
    className: "neo-input",
    type: "password",
    id: "tb-cur-pass",
    placeholder: "Current password"
  })), React.createElement("div", null, React.createElement("label", {
    className: "field-label fl-c-purple"
  }, "New password"), React.createElement("input", {
    className: "neo-input",
    type: "password",
    id: "tb-new-pass",
    placeholder: "min 4 characters"
  }))), React.createElement("div", {
    className: "nb-card-f space-y-2"
  }, React.createElement("button", {
    type: "button",
    onClick: async function () {
      var c = (document.getElementById("tb-cur-pass") || {}).value || "";
      var n = (document.getElementById("tb-new-pass") || {}).value || "";
      if (!n || n.length < 4) return onToast("New password min 4 chars", true);
      try {
        var res = await fetch("/api/change-password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({ current_password: c, new_password: n })
        });
        var j = await res.json().catch(function () { return {}; });
        if (!res.ok) return onToast(j.error || "Password change failed", true);
        onToast("Password updated", "success");
      } catch (e) {
        onToast("Password change failed", true);
      }
    },
    className: "w-full min-h-[46px] flex items-center justify-center gap-2 bg-[#7c3aed] text-white border-[2.5px] border-black shadow-[3px_3px_0_#000] font-black text-sm"
  }, React.createElement("span", {
    className: "material-symbols-outlined",
    style: { fontSize: 18, color: "#fff" }
  }, "lock_reset"), "Change Password"), React.createElement("button", {
    type: "button",
    onClick: async function () {
      try {
        await fetch("/api/logout", { method: "POST", credentials: "same-origin" });
      } catch (e) {}
      location.replace("/login");
    },
    className: "w-full min-h-[46px] flex items-center justify-center gap-2 bg-[#dc2626] text-white border-[2.5px] border-black shadow-[3px_3px_0_#000] font-black text-sm"
  }, React.createElement("span", {
    className: "material-symbols-outlined",
    style: { fontSize: 18, color: "#fff" }
  }, "logout"), "Logout")))), tab === "update" && React.createElement("div", {
    className: "anim-pop"
  }, React.createElement("div", {
    className: "nb-card"
  }, React.createElement("div", {
    className: "nb-card-h flex items-center gap-3",
    style: { background: "#f9a8d4" }
  }, React.createElement("div", {
    className: "w-9 h-9 bg-[#db2777] border-[2.5px] border-black flex items-center justify-center shrink-0 shadow-[2px_2px_0_#000]"
  }, React.createElement("span", {
    className: "material-symbols-outlined",
    style: { fontSize: 18, color: "#fff" }
  }, "rocket_launch")), React.createElement("div", null, React.createElement("div", {
    className: "t",
    style: { color: "#000" }
  }, "Update panel"), React.createElement("div", { className: "d" }, "Pull the latest build"))), React.createElement("div", {
    className: "nb-card-b space-y-3"
  }, React.createElement("label", {
    className: "field-label fl-c-blue"
  }, "Download and apply the latest panel from GitHub."), React.createElement("button", {
    type: "button",
    disabled: updating,
    onClick: async function () {
      setUpdating(true);
      try {
        var res = await fetch("/api/update-panel", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({})
        });
        var j = await res.json().catch(function () { return {}; });
        if (!res.ok) {
          onToast(j.error || "Update failed", true);
          return;
        }
        onToast(j.message || "Updated - reloading...", "success");
        try { setTimeout(function () { location.reload(); }, 1600); } catch (eR) {}
      } catch (e) {
        onToast("Update failed", true);
      } finally {
        setUpdating(false);
      }
    },
    className: "w-full min-h-[56px] flex items-center justify-center gap-2 bg-[#db2777] text-white border-[2.5px] border-black shadow-[3px_3px_0_#000] font-black text-sm disabled:opacity-60"
  }, React.createElement("span", {
    className: "material-symbols-outlined",
    style: { fontSize: 22, color: "#fff" }
  }, "rocket_launch"), updating ? "Updating..." : "Update from GitHub")))), tab === "system" && React.createElement("div", {
    className: "anim-pop"
  }, React.createElement("div", {
    className: "nb-card"
  }, React.createElement("div", {
    className: "nb-card-h flex items-center gap-3",
    style: { background: "#86efac" }
  }, React.createElement("div", {
    className: "w-9 h-9 bg-[#22c55e] border-[2.5px] border-black flex items-center justify-center shrink-0 shadow-[2px_2px_0_#000]"
  }, React.createElement("span", {
    className: "material-symbols-outlined",
    style: { fontSize: 18, color: "#000" }
  }, "dns")), React.createElement("div", null, React.createElement("div", {
    className: "t",
    style: { color: "#000" }
  }, "System"), React.createElement("div", { className: "d" }, "Backup export & import"))), React.createElement("div", {
    className: "nb-card-b"
  }, React.createElement("label", {
    className: "field-label fl-c-blue mb-3"
  }, "Export or import panel data."), React.createElement("div", {
    className: "grid grid-cols-2 gap-3"
  }, React.createElement("button", {
    type: "button",
    onClick: async function () {
      try {
        var res = await fetch("/api/users?t=" + Date.now(), { credentials: "same-origin" });
        if (!res.ok) throw new Error("fail");
        var data = await res.json();
        var list = Array.isArray(data) ? data : data.users || data.results || [];
        var blob = new Blob([JSON.stringify({ users: list, exported_at: new Date().toISOString() }, null, 2)], { type: "application/json" });
        var a = document.createElement("a");
        var rnd = "";
        var chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        for (var i = 0; i < 6; i++) rnd += chars.charAt(Math.floor(Math.random() * chars.length));
        a.href = URL.createObjectURL(blob);
        a.download = "TrexBridge-backup-" + rnd + ".json";
        document.body.appendChild(a);
        a.click();
        a.remove();
        onToast("Exported " + list.length + " users", "success");
      } catch (e) {
        onToast("Export failed", true);
      }
    },
    className: "min-h-[88px] flex flex-col items-center justify-center gap-1.5 bg-[#dc2626] text-white border-[2.5px] border-black shadow-[3px_3px_0_#000] font-black text-sm"
  }, React.createElement("span", {
    className: "material-symbols-outlined",
    style: { fontSize: 28, color: "#fff" }
  }, "upload"), "Export"), React.createElement("button", {
    type: "button",
    onClick: function () {
      var inp = document.getElementById("tb-import-file");
      if (inp) inp.click();
    },
    className: "min-h-[88px] flex flex-col items-center justify-center gap-1.5 bg-[#facc15] border-[2.5px] border-black shadow-[3px_3px_0_#000] font-black text-sm relative"
  }, React.createElement("input", {
    id: "tb-import-file",
    type: "file",
    accept: ".json,application/json",
    className: "hidden",
    onChange: async function (e) {
      var file = e.target.files && e.target.files[0];
      e.target.value = "";
      if (!file) return;
      try {
        var text = await file.text();
        var parsed = JSON.parse(text);
        var users = Array.isArray(parsed) ? parsed : parsed.users || [];
        var ok = 0, fail = 0;
        for (var ui = 0; ui < users.length; ui++) {
          var u = users[ui];
          if (!u || !u.username) continue;
          try {
            var res = await fetch("/api/users", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              credentials: "same-origin",
              body: JSON.stringify(u)
            });
            if (res.ok) ok++; else fail++;
          } catch (err) { fail++; }
        }
        onToast("Import: " + ok + " ok" + (fail ? ", " + fail + " failed" : ""), fail && !ok ? true : "success");
      } catch (err) {
        onToast("Import failed", true);
      }
    }
  }), React.createElement("span", {
    className: "material-symbols-outlined",
    style: { fontSize: 28 }
  }, "download"), "Import"))))));
}

ReactDOM.createRoot(document.getElementById("root")).render(/*#__PURE__*/React.createElement(TrexBridgePanel, null));
  } catch(err) {
    console.error(err);
    showBootErr("Panel error: "+(err&&err.message?err.message:String(err)));
  }
})();
</script>
</body>
</html>
`,
	status: `<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>TrexBridge — Status</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700;800;900&family=Public+Sans:wght@600;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #f5f0e8;
    --card: #fffdf5;
    --ink: #0a0a0a;
    --muted: #71717a;
    --green: #22c55e;
    --lime: #bef264;
    --yellow: #facc15;
    --sky: #f9a8d4;
    --red: #ef4444;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; border-radius: 0 !important; }
  body {
    font-family: "Public Sans", system-ui, sans-serif;
    font-weight: 700;
    background: var(--bg);
    color: var(--ink);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 16px 12px;
    overflow-x: hidden;
  }
  .grid-bg { position:fixed; inset:-20px; z-index:0; pointer-events:none; background-color:#f5f0e8;
      background-image:linear-gradient(to right,rgba(0,0,0,.11) 1.5px,transparent 1.5px),linear-gradient(to bottom,rgba(0,0,0,.11) 1.5px,transparent 1.5px);
      background-size:40px 40px; background-position:-12px -12px; }
  @keyframes gridDrift {
    0% { background-position: 0 0; }
    100% { background-position: 36px 36px; }
  }
  .card {
    position: relative; z-index: 1;
    width: 100%;
    max-width: 540px;
    background: var(--card);
    border: 3.5px solid #000;
    box-shadow: 6px 6px 0 #000;
    padding: 1.25rem 1.1rem;
  }
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.25rem;
    gap: 12px;
  }
  .brand {
    display: flex;
    align-items: center;
    font-family: Archivo, sans-serif;
    font-size: 1.45rem;
    font-weight: 900;
    letter-spacing: -0.5px;
  }
  .brand-box {
    position: relative;
    overflow: hidden;
    background: var(--green);
    padding: 3px 10px;
    border: 2.5px solid #000;
    box-shadow: 3px 3px 0 #000;
  }
  .brand-box::after {
    content: "";
    position: absolute; top: 0; bottom: 0; left: -60%; width: 40%;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.45), transparent);
    transform: skewX(-18deg);
    animation: shine 3.8s ease-in-out infinite;
  }
  @keyframes shine { 0% { left: -60%; } 100% { left: 130%; } }
  .brand-bridge { padding-left: 8px; }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 0.4rem 0.9rem;
    border: 3px solid #000;
    background: #fff;
    box-shadow: 3px 3px 0 #000;
    font-size: 0.78rem;
    font-weight: 800;
  }
  .badge-dot {
    width: 10px; height: 10px;
    background: var(--green);
    border: 2px solid #000;
    animation: pulse 1.6s ease-in-out infinite;
  }
  .badge-dot.inactive { background: var(--red); animation: none; }
  @keyframes pulse {
    0%, 100% { transform: scale(1); }
    50% { transform: scale(1.35); }
  }
  .stats {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 8px;
    margin-bottom: 1.15rem;
  }
  .stat {
    text-align: center;
    padding: 12px 4px;
    border: 3px solid #000;
    background: #fff;
    box-shadow: 3px 3px 0 #000;
  }
  .stat:hover {
    transform: translate(-2px, -2px);
    box-shadow: 5px 5px 0 #000;
    background: var(--lime);
  }
  .stat-label {
    font-size: 0.65rem;
    font-weight: 800;
    color: var(--muted);
    text-transform: uppercase;
  }
  .stat-value {
    font-family: Archivo, sans-serif;
    font-size: 1.05rem;
    font-weight: 900;
    margin-top: 4px;
  }
  .stat-value.highlight {
    background: var(--yellow);
    display: inline-block;
    padding: 1px 6px;
    border: 2px solid #000;
  }
  .progress-section { margin-bottom: 1.15rem; }
  .progress-header {
    display: flex;
    justify-content: space-between;
    font-size: 0.82rem;
    font-weight: 800;
    margin-bottom: 8px;
  }
  .progress-bar {
    height: 18px;
    background: #fff;
    border: 3px solid #000;
    overflow: hidden;
  }
  .progress-fill {
    height: 100%;
    width: 0%;
    background: var(--green);
    border-right: 2.5px solid #000;
    transition: width 0.8s cubic-bezier(0.34, 1.56, 0.64, 1);
  }
  .info-box {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.75rem 1rem;
    border: 3px solid #000;
    background: #fff;
    box-shadow: 3px 3px 0 #000;
    margin-bottom: 1.15rem;
  }
  .info-label { font-size: 0.8rem; font-weight: 800; color: var(--muted); }
  .info-value { font-size: 0.95rem; font-weight: 900; }
  .links-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
  }
  .links-title { font-size: 0.88rem; font-weight: 900; font-family: Archivo, sans-serif; }
  .btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 0.45rem 0.9rem;
    border: 2.5px solid #000;
    background: #fff;
    box-shadow: 2.5px 2.5px 0 #000;
    font-family: inherit;
    font-weight: 800;
    font-size: 0.75rem;
    cursor: pointer;
    color: #000;
    text-decoration: none;
  }
  .btn-yellow { background: var(--yellow); }
  .btn-sky { background: #7dd3fc; }
  .btn-pink { background: #f9a8d4; }
  .links-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
    max-height: 240px;
    overflow-y: auto;
    margin-bottom: 1.15rem;
  }
  .links-list::-webkit-scrollbar { width: 10px; }
  .links-list::-webkit-scrollbar-track { background: #e8e0d4; border-left: 2px solid #000; }
  .links-list::-webkit-scrollbar-thumb { background: var(--green); border: 2px solid #000; }
  .link-item {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 12px;
    border: 2.5px solid #000;
    background: #fff;
    box-shadow: 2.5px 2.5px 0 #000;
  }
  .link-url {
    flex: 1;
    min-width: 0;
    font-family: ui-monospace, monospace;
    font-size: 0.68rem;
    font-weight: 600;
    color: var(--muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .copy-btn {
    flex-shrink: 0;
    padding: 6px 12px;
    border: 2.5px solid #000;
    background: #fff;
    box-shadow: 2px 2px 0 #000;
    font-family: inherit;
    font-weight: 800;
    font-size: 0.7rem;
    cursor: pointer;
  }
  .copy-btn.copied { background: var(--green); }
  .actions {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding-top: 1.1rem;
    border-top: 3.5px solid #000;
  }
  .btn-full {
    color: #000 !important;
    width: 100%;
    min-height: 48px;
    font-size: 0.85rem;
    padding: 0.7rem 1rem;
    box-shadow: 3.5px 3.5px 0 #000;
    justify-content: center;
  }
  .btn-tg { background: #38bdf8; color: #000 !important; }
  .btn-gh { background: #a78bfa; color: #000 !important; }
  .footer {
    margin-top: 1rem;
    text-align: center;
    font-size: 0.68rem;
    font-weight: 700;
    color: var(--muted);
  }
  #toast-wrap {
    position: fixed; left: 0; right: 0; bottom: 24px; z-index: 9999;
    display: flex; flex-direction: column; align-items: center; gap: 8px;
    pointer-events: none; padding: 0 12px;
  }
  .tb-toast {
    background: #fff; border: 3px solid #000; box-shadow: 4px 4px 0 #000;
    padding: 0.85rem 1.15rem; font-weight: 800; font-size: 0.88rem;
    max-width: min(400px, 92vw); opacity: 0; transform: translateY(12px);
    transition: opacity 0.22s, transform 0.28s cubic-bezier(0.34,1.56,0.64,1);
  }
  .tb-toast.show { opacity: 1; transform: translateY(0); }
  .sub-toolbar {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-bottom: 12px;
  }
  .sub-split {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
  }
  .btn-half {
    width: 100%;
    min-height: 48px;
    justify-content: center;
    font-size: 0.82rem;
    box-shadow: 3.5px 3.5px 0 #000;
  }
  .link-item {
    direction: ltr;
    text-align: left;
  }
  .link-url { text-align: left; }
  .copy-btn { margin-left: auto; }
  #qrModal {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 10000;
    background: rgba(10,10,10,.55);
    align-items: center;
    justify-content: center;
    padding: max(12px, 3vw);
  }
  #qrModal.show { display: flex; }
  #qrModal .qr-card {
    width: min(280px, 78vw);
    display: flex;
    flex-direction: column;
    align-items: stretch;
    gap: 10px;
    background: transparent;
    border: none;
    box-shadow: none;
  }
  #qrModal .qr-top {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
  }
  #qrModal .qr-x {
    flex-shrink: 0;
    width: 40px;
    height: 40px;
    border: 2.5px solid #000;
    background: #ef4444;
    color: #fff;
    font-weight: 900;
    font-size: 20px;
    line-height: 1;
    cursor: pointer;
    box-shadow: 2px 2px 0 #000;
  }
  #qrModal .qr-chip {
    flex: 1;
    min-width: 0;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px;
    border: 2.5px solid #000;
    box-shadow: 2px 2px 0 #000;
    font-weight: 900;
    font-size: 13px;
    text-align: left;
    overflow: hidden;
  }
  #qrModal .qr-chip span {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  #qrModal .qr-body {
    width: 100%;
    box-sizing: border-box;
    padding: 12px;
    background: #fef9c3;
    border: 3px solid #000;
    box-shadow: 4px 4px 0 #000;
    display: flex;
    justify-content: center;
  }
  #qrModal img {
    width: 100%;
    height: auto;
    display: block;
    background: #fff;
  }
  @media (max-width: 480px) {
    .stats { grid-template-columns: repeat(2, 1fr); }
  }
</style>
</head>
<body>
<div class="grid-bg"></div>
<div class="card">
  <div class="header">
    <div class="brand">
      <span class="brand-box">Trex</span>
      <span class="brand-bridge">Bridge</span>
    </div>
    <span class="badge">
      <span class="badge-dot" id="badgeDot"></span>
      <span id="badgeText">Active</span>
    </span>
  </div>
  <div class="stats">
    <div class="stat"><div class="stat-label">Usage</div><div class="stat-value" id="stUsed">—</div></div>
    <div class="stat"><div class="stat-label">Limit</div><div class="stat-value" id="stLimit">—</div></div>
    <div class="stat"><div class="stat-label">Remain</div><div class="stat-value highlight" id="stRem">—</div></div>
    <div class="stat"><div class="stat-label">Days</div><div class="stat-value" id="stDays">—</div></div>
  </div>
  <div class="progress-section">
    <div class="progress-header"><span>Traffic usage</span><span id="progressPercent">0%</span></div>
    <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
  </div>
  <div class="info-box">
    <span class="info-label">User</span>
    <span class="info-value" id="stUser">—</span>
  </div>
  <div class="sub-toolbar">
    <div class="sub-split">
      <button type="button" class="btn btn-half btn-sky" id="copySubBtn" style="background:#38bdf8;color:#000;font-weight:900;border:2.5px solid #000;box-shadow:3px 3px 0 #000">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
        Copy sub URL
      </button>
      <button type="button" class="btn btn-half btn-pink" id="toggleQrBtn" style="background:#c4b5fd;color:#000;font-weight:900;border:2.5px solid #000">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h3v3h-3zM20 14v6M14 20h3"/></svg>
        QR code
      </button>
    </div>
    <button type="button" class="btn btn-full btn-yellow" id="copyAllBtn" style="background:#eab308;color:#000;font-weight:900;border:2.5px solid #000;box-shadow:3px 3px 0 #000">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
      Copy all
    </button>
  </div>
  <div id="qrModal" aria-hidden="true">
    <div class="qr-card">
      <div class="qr-top">
        <div class="qr-chip" id="qrChip">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h3v3h-3zM20 14v6M14 20h3"/></svg>
          <span id="qrChipName">user</span>
        </div>
        <button type="button" class="qr-x" id="qrCloseBtn" aria-label="Close">×</button>
      </div>
      <div class="qr-body">
        <img id="qrImg" alt="QR"/>
      </div>
    </div>
  </div>
  <div class="links-list" id="linksList">
    <div style="text-align:center;padding:1.2rem;border:2.5px dashed #000;background:#fff;font-weight:800;color:var(--muted);font-size:.85rem;">Loading...</div>
  </div>
  <div class="actions">
    <a href="https://t.me/TrexBridgePanel" class="btn btn-full btn-tg" target="_blank" rel="noopener">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
      </svg>
      Support
    </a>
    <a href="https://github.com/icubaby/TrexBridge" class="btn btn-full btn-gh" target="_blank" rel="noopener">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/>
      </svg>
      GitHub
    </a>
  </div>
  <div class="footer">TrexBridge · subscription · v3</div>
</div>
<div id="toast-wrap"></div>
<script>
/* {{USER_DATA_PLACEHOLDER}} */

function showToast(text, type) {
  var kind = "info";
  if (type === true || type === "error" || type === "err") kind = "error";
  else if (type === "success" || type === "ok") kind = "success";
  else if (type === "ping") kind = "ping";
  else if (type === "copy") kind = "copy";
  else if (type === false || type == null || type === "info") kind = "info";
  else if (typeof type === "string") kind = type;
  var icons = {
    error: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg>',
    success: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="M22 4L12 14.01l-3-3"/></svg>',
    ping: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.5"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><circle cx="12" cy="20" r="1.2" fill="#000" stroke="none"/></svg>',
    copy: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
    info: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="2.4"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>'
  };
  var colors = { error: "#fda4af", success: "#4ade80", ping: "#22c55e", copy: "#facc15", info: "#fde68a" };
  var bars = { error: "#e11d48", success: "#16a34a", ping: "#15803d", copy: "#ca8a04", info: "#eab308" };
  var wrap = document.getElementById("toast-wrap");
  if (!wrap) {
    wrap = document.createElement("div");
    wrap.id = "toast-wrap";
    wrap.style.cssText = "position:fixed;left:0;right:0;bottom:24px;z-index:9999;display:flex;flex-direction:column;align-items:center;gap:8px;pointer-events:none;padding:0 12px;";
    document.body.appendChild(wrap);
  }
  while (wrap.children.length >= 5) { try { wrap.removeChild(wrap.firstChild); } catch(e) { break; } }
  var t = document.createElement("div");
  t.setAttribute("role", "status");
  t.style.cssText = "position:relative;overflow:hidden;background:#fff;border:3px solid #000;box-shadow:4px 4px 0 #000;padding:0.85rem 1.15rem 0.75rem 1rem;font-weight:800;font-size:0.88rem;display:flex;align-items:center;gap:10px;width:max-content;max-width:min(400px,92vw);opacity:0;transform:translateY(14px);transition:opacity .22s ease,transform .28s cubic-bezier(.34,1.56,.64,1);";
  var bar = document.createElement("div");
  bar.style.cssText = "position:absolute;top:0;left:0;right:0;height:5px;border-bottom:2px solid #000;background:" + (bars[kind] || bars.info) + ";";
  var icon = document.createElement("span");
  icon.style.cssText = "width:32px;height:32px;border:2.5px solid #000;background:" + (colors[kind] || colors.info) + ";display:inline-flex;align-items:center;justify-content:center;box-shadow:2px 2px 0 #000;flex-shrink:0;";
  icon.innerHTML = icons[kind] || icons.info;
  var msg = document.createElement("span");
  msg.style.cssText = "flex:1;text-align:left;line-height:1.35;";
  msg.textContent = String(text || "");
  t.appendChild(bar);
  t.appendChild(icon);
  t.appendChild(msg);
  wrap.appendChild(t);
  for (var si = 0; si < wrap.children.length; si++) {
    var age = wrap.children.length - 1 - si;
    wrap.children[si].style.opacity = String(Math.max(0.35, 1 - age * 0.14));
  }
  requestAnimationFrame(function(){ t.style.opacity = "1"; t.style.transform = "translateY(0)"; });
  setTimeout(function(){
    t.style.opacity = "0";
    t.style.transform = "translateY(10px)";
    setTimeout(function(){ try { t.remove(); } catch(e) {} }, 260);
  }, 2600);
}

function fmtTraffic(gb) {
  var n = Number(gb);
  if (!n || n <= 0 || isNaN(n)) return "0 B";
  var bytes = n * 1024 * 1024 * 1024;
  if (bytes < 1024) return bytes.toFixed(0) + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + " GB";
}
function getHost() { return window.location.hostname; }
function buildLinks() {
  var u = window.statusUser;
  if (!u) return [];
  // Server-built links already include fragment (preferred)
  if (u.config_links && u.config_links.length) {
    return u.config_links.map(function(url) {
      return { url: String(url) };
    });
  }
  var host = getHost();
  var ips = [host];
    if (u.ips) {
    var tmp = String(u.ips);
    var parts = [];
    var buf = "";
    for (var ii = 0; ii < tmp.length; ii++) {
      var code = tmp.charCodeAt(ii);
      if (code === 10 || code === 13 || tmp.charAt(ii) === ",") {
        if (buf.trim()) parts.push(buf.trim());
        buf = "";
      } else buf += tmp.charAt(ii);
    }
    if (buf.trim()) parts.push(buf.trim());
    if (parts.length) {
      ips = [];
      for (var pi = 0; pi < parts.length; pi++) {
        var pv = String(parts[pi]).trim();
        if (!pv) continue;
        if (pv.toLowerCase() === String(host).toLowerCase()) continue;
        if (/\.workers\.dev$/i.test(pv)) continue;
        ips.push(pv);
      }
      if (!ips.length) ips = [host];
    }
  }
var ports = String(u.port || "443").split(",").map(function(p){ return p.trim(); }).filter(Boolean);
  if (!ports.length) ports = ["443"];
  var fp = u.fingerprint || "chrome";
  var rawPath = "/api/ws";
  var fProtos = ["vless"];
  var fragQ = "&fragment=" + encodeURIComponent("tlshello,5,94,1,0") + "&fragment2=" + encodeURIComponent("1-1,109,1,1,355");
  try {
    var _raw = u.frag_len ? String(u.frag_len) : "";
    if (_raw) {
      if (_raw.indexOf("default") >= 0 && _raw.indexOf("flux") < 0 && _raw.indexOf("trex") < 0 && _raw.indexOf("packets2") < 0) {
        fragQ = "&fragment=" + encodeURIComponent("tlshello,100-200,1-1,100-200");
      }
      if (_raw.indexOf("trex") >= 0 || _raw.indexOf("flux") >= 0 || _raw.indexOf("packets2") >= 0 || _raw.indexOf("5,94,1") >= 0 || _raw.indexOf("dual") >= 0) {
        fragQ = "&fragment=" + encodeURIComponent("tlshello,5,94,1,0") + "&fragment2=" + encodeURIComponent("1-1,109,1,1,355");
      }
      if (_raw.charAt(0) === "{") {
        var _fj = JSON.parse(_raw);
        if (_fj.protocols) {
          fProtos = String(_fj.protocols).split(",").map(function(p){ return p.trim().toLowerCase(); }).filter(Boolean);
          if (!fProtos.length) fProtos = ["vless"];
        }
        if (fProtos.indexOf("vless") < 0 && fProtos.indexOf("trojan") < 0) fProtos = ["vless"];
        var _m = String(_fj.mode || "").toLowerCase();
        if (_m === "default" || _m === "normal") {
          fragQ = "&fragment=" + encodeURIComponent("tlshello,100-200,1-1,100-200");
        } else if (_m === "trex" || _m === "flux" || _fj.dual || _fj.packets2) {
          fragQ = "&fragment=" + encodeURIComponent("tlshello,5,94,1,0") + "&fragment2=" + encodeURIComponent("1-1,109,1,1,355");
        }
      }
    }
  } catch(e) {}
  var links = [];
  function toBoldSans(str) {
    var out = "";
    for (var bi = 0; bi < String(str || "").length; bi++) {
      var c = String(str).charCodeAt(bi);
      if (c >= 65 && c <= 90) out += String.fromCodePoint(0x1D5D4 + (c - 65));
      else if (c >= 97 && c <= 122) out += String.fromCodePoint(0x1D5EE + (c - 97));
      else if (c >= 48 && c <= 57) out += String.fromCodePoint(0x1D7EC + (c - 48));
      else out += String(str).charAt(bi);
    }
    return out;
  }
  function buildRemark(proto) {
    var uname = String(u.username || "user");
    var m = uname.match(/^TrexBridge[-_]?(.+)$/i);
    var namePart;
    if (m) {
      var rnd = String(m[1] || "").replace(/[^a-zA-Z0-9]/g, "");
      namePart = (rnd.slice(0, 3) || "x").toLowerCase();
    } else {
      namePart = uname;
    }
    return "🦖 - " + toBoldSans("TrexBridge") + "-" + toBoldSans(namePart);
  }
  if (!fragQ || fragQ.indexOf("fragment=") < 0) {
    fragQ = "&fragment=" + encodeURIComponent("tlshello,5,94,1,0") + "&fragment2=" + encodeURIComponent("1-1,109,1,1,355");
  }
  ips.forEach(function(ip) {
    ports.forEach(function(portStr) {
      var isTls = ["443","2053","2083","2087","2096","8443"].indexOf(portStr) >= 0;
      var tlsVal = isTls ? "tls" : "none";
      var path = encodeURIComponent(rawPath);
      if (fProtos.indexOf("vless") >= 0) {
        var remarkV = buildRemark("vless");
        links.push({ url: "vless://" + (u.uuid || "") + "@" + ip + ":" + portStr
          + "?path=" + path + "&security=" + tlsVal + "&encryption=none&insecure=0&host=" + host
          + "&fp=" + fp + "&type=ws&allowInsecure=0&sni=" + host + fragQ
          + "#" + encodeURIComponent(remarkV) });
      }
      if (fProtos.indexOf("trojan") >= 0) {
        var trojanAlpn = tlsVal === "tls" ? "&alpn=http%2F1.1" : "";
        var remarkT = buildRemark("trojan");
        links.push({ url: "trojan://" + (u.uuid || "") + "@" + ip + ":" + portStr
          + "?path=" + path + "&security=" + tlsVal + "&type=ws&host=" + host + "&fp=" + fp
          + "&sni=" + host + "&allowInsecure=0" + trojanAlpn + fragQ
          + "#" + encodeURIComponent(remarkT) });
      }
    });
  });
  return links;
}
function copyText(text, btn, msg) {
  function done() {
    showToast(msg || "Config copied", "copy");
    if (btn) {
      btn.classList.add("copied");
      var old = btn.textContent;
      btn.textContent = "OK";
      setTimeout(function(){ btn.classList.remove("copied"); btn.textContent = old; }, 1200);
    }
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done).catch(function(){
      var ta = document.createElement("textarea");
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); done(); } catch(e) { showToast("Copy failed"); }
      document.body.removeChild(ta);
    });
  } else {
    var ta = document.createElement("textarea");
    ta.value = text; document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); done(); } catch(e) { showToast("Copy failed"); }
    document.body.removeChild(ta);
  }
}
document.addEventListener("DOMContentLoaded", function() {
  var u = window.statusUser;
  if (!u) {
    document.getElementById("badgeText").textContent = "Not found";
    document.getElementById("badgeDot").classList.add("inactive");
    document.getElementById("linksList").innerHTML = '<div style="text-align:center;padding:1.2rem;border:2.5px dashed #000;background:#fff;font-weight:800;color:var(--muted);font-size:.85rem;">User not found</div>';
    return;
  }
  var used = Number(u.used_gb || 0);
  var limit = (u.limit_gb != null && u.limit_gb !== "") ? Number(u.limit_gb) : null;
  var rem = (limit != null && !isNaN(limit)) ? Math.max(0, limit - used) : null;
  var pct = 0;
  if (limit != null && limit > 0) {
    pct = (used / limit) * 100;
    if (pct > 100) pct = 100;
  }
  document.getElementById("stUsed").textContent = fmtTraffic(used);
  document.getElementById("stLimit").textContent = fmtTraffic(limit);
  document.getElementById("stRem").textContent = fmtTraffic(rem);
  var stEl = document.getElementById("stUser");
  stEl.textContent = u.username || "—";
  try {
    var cols = ["#facc15","#7dd3fc","#a78bfa","#f9a8d4","#86efac","#fdba74","#fde68a","#c4b5fd"];
    var h = 0, n = String(u.username || "");
    for (var i = 0; i < n.length; i++) h = (h * 31 + n.charCodeAt(i)) >>> 0;
    stEl.style.cssText = "display:inline-block;padding:4px 10px;border:2.5px solid #000;box-shadow:2px 2px 0 #000;background:" + cols[h % cols.length] + ";";
  } catch (eSU) {}
  var days = "Unlimited";
  var expired = false;
  if (u.expiry_days && u.created_at) {
    var created = new Date(u.created_at).getTime();
    var exp = created + Number(u.expiry_days) * 86400000;
    var d = Math.ceil((exp - Date.now()) / 86400000);
    if (d <= 0) { days = "Expired"; expired = true; }
    else days = d + "d";
  }
  document.getElementById("stDays").textContent = days;
  var active = u.is_active !== 0 && !expired;
  document.getElementById("badgeText").textContent = active ? "Active" : "Inactive";
  if (!active) document.getElementById("badgeDot").classList.add("inactive");
  var pctLabel = (limit != null && limit > 0)
    ? (pct < 0.1 && used > 0 ? pct.toFixed(2) : (pct < 1 ? pct.toFixed(1) : pct.toFixed(0))) + "%"
    : (used > 0 ? "Used" : "0%");
  document.getElementById("progressPercent").textContent = pctLabel;
  var fill = document.getElementById("progressFill");
  setTimeout(function() {
    if (limit != null && limit > 0) {
      var w = pct;
      if (used > 0 && w < 1.5) w = 1.5;
      fill.style.width = w + "%";
    } else if (used > 0) {
      fill.style.width = "8%";
    } else {
      fill.style.width = "0%";
    }
  }, 200);
  var links = buildLinks();
  var list = document.getElementById("linksList");
  if (!links.length && u && u.uuid) {
    try {
      var h = window.location.hostname;
      var frag = "&fragment=" + encodeURIComponent("tlshello,5,94,1,0") + "&fragment2=" + encodeURIComponent("1-1,109,1,1,355");
      links.push({ url: "vless://" + u.uuid + "@" + h + ":443?path=" + encodeURIComponent("/api/ws") + "&security=tls&encryption=none&insecure=0&host=" + h + "&fp=" + (u.fingerprint||"chrome") + "&type=ws&allowInsecure=0&sni=" + h + frag + "#" + encodeURIComponent("🦖 - " + (u.username||"")) });
    } catch (eLR) {}
  }
  if (!links.length) {
    list.innerHTML = '<div style="text-align:center;padding:1.2rem;border:2.5px dashed #000;background:#fff;font-weight:800;color:var(--muted);font-size:.85rem;">No configs available</div>';
  } else {
    list.innerHTML = links.map(function(item, i) {
      return '<div class="link-item"><div class="link-url">' + item.url.replace(/</g,"&lt;") + '</div><button type="button" class="copy-btn" data-i="' + i + '">Copy</button></div>';
    }).join("");
    list.querySelectorAll(".copy-btn").forEach(function(btn) {
      btn.addEventListener("click", function() {
        var i = parseInt(btn.getAttribute("data-i"), 10);
        copyText(links[i].url, btn);
      });
    });
  }
  document.getElementById("copyAllBtn").addEventListener("click", function() {
    if (!links.length) return showToast("No configs", "error");
    copyText(links.map(function(l){ return l.url; }).join(String.fromCharCode(10)), null, "All configs copied");
  });
  try {
    var subUrlRaw = window.location.origin + "/export/" + encodeURIComponent(u.username || "") + "?raw=1";
    var subUrl = window.location.origin + "/export/" + encodeURIComponent(u.username || "");
    var copySub = document.getElementById("copySubBtn");
    if (copySub) copySub.onclick = function(){ copyText(subUrl, null, "Subscription copied"); };
    var tq = document.getElementById("toggleQrBtn");
    var modal = document.getElementById("qrModal");
    var qrImg = document.getElementById("qrImg");
    var qrChip = document.getElementById("qrChip");
    var qrClose = document.getElementById("qrCloseBtn");
    if (tq && modal && qrImg) {
      tq.onclick = function(){
        var name = String(u.username || "user");
        var cols = ["#facc15","#7dd3fc","#a78bfa","#f9a8d4","#86efac","#fdba74","#fde68a","#c4b5fd"];
        var h = 0;
        for (var ci = 0; ci < name.length; ci++) h = (h * 31 + name.charCodeAt(ci)) >>> 0;
        var chipCol = cols[h % cols.length];
        if (qrChip) {
          qrChip.style.background = chipCol;
          var nm = document.getElementById("qrChipName");
          if (nm) nm.textContent = name;
        }
        var bgHex = String(chipCol).replace("#", "");
        qrImg.src = "https://api.qrserver.com/v1/create-qr-code/?size=320x320&margin=14&color=0a0a0a&bgcolor=" + bgHex + "&data=" + encodeURIComponent(subUrlRaw);
        try {
          var body = qrImg.parentElement;
          if (body) body.style.background = chipCol;
        } catch (eB) {}
        modal.classList.add("show");
        modal.setAttribute("aria-hidden", "false");
      };
      function closeQr(){ modal.classList.remove("show"); modal.setAttribute("aria-hidden", "true"); }
      if (qrClose) qrClose.onclick = closeQr;
      modal.onclick = function(e){ if (e.target === modal) closeQr(); };
    }
  } catch(eSub) {}
});
</script>
</body>
</html>
`,
};

export default __WORKER_EXPORT__
