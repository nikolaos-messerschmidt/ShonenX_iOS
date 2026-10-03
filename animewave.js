const mangayomiSources = [
    {
        "name": "AnimeWave",
        "id": 148203771,
        "lang": "en",
        "baseUrl": "https://animewave.to",
        "apiUrl": "",
        "iconUrl": "https://www.google.com/s2/favicons?sz=256&domain=https://animewave.to",
        "typeSource": "single",
        "itemType": 1,
        "version": "0.2.0",
        "isManga": false,
        "isNsfw": false,
        "hasCloudflare": false,
        "isFullData": false,
        "appMinVerReq": "0.5.0",
        "sourceCodeUrl": "https://raw.githubusercontent.com/nikolaos-messerschmidt/ShonenX_iOS/refs/heads/main/animewave.js",
        "dateFormat": "",
        "dateFormatLocale": "",
        "additionalParams": "",
        "sourceCodeLanguage": 1,
        "notes": "",
    },
];
// V13
// AnimeWave (animewave.to) — 9anime/AniWave-family template with a
// MegaPlay-only player backend.
//
// V10 changes: MegaPlay now returns its m3u8 AES-256-CBC-encrypted inside
// the "enc" field of getSources/getSourcesNew, and the CDN requires a
// signed HMAC-SHA256 token on the m3u8 URL. Both crypto steps are now
// implemented in pure JS below (no CryptoJS / no extensions required).
//
// Endpoints used (all unauthenticated ajax):
//   /filter?...                              -> browse/search results
//   /ajax/episode/list/{animeId}             -> episode <li> list with data-ids
//   /ajax/server/list?servers={data-ids}    -> sub/dub <li data-link-id>
//   /ajax/server?get={link-id}               -> {result:{url:"<megaplay url>"}}
//   megaplay.../stream/...                   -> HTML with data-id
//   megaplay.../stream/getSources(New)      -> {enc:"...", intro, outro, tracks}
//                                                (enc = AES-encrypted {"file":"...m3u8"})

// ══════════════════════════════════════════════════════════════════════════
//  PURE-JS CRYPTO (AES-256-CBC decrypt, SHA-256, HMAC-SHA256, Base64)
//  No dependencies. QuickJS / plain JS compatible.
// ══════════════════════════════════════════════════════════════════════════

var MegaCrypto = (function () {
    "use strict";

    // ── AES S-box (inverse computed at runtime) ─────────────────────────────
    var SBOX = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    ];
    var INV_SBOX = new Array(256);
    for (var i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i;

    var RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d];

    // ── Galois field multiply (GF(2^8), poly x^8+x^4+x^3+x+1) ────────────────
    function gmul(a, b) {
        var p = 0;
        for (var i = 0; i < 8; i++) {
            if (b & 1) p ^= a;
            var hi = a & 0x80;
            a = (a << 1) & 0xff;
            if (hi) a ^= 0x1b;
            b >>= 1;
        }
        return p;
    }

    // ── AES key expansion (works for 128/192/256, we use 256) ──────────────
    function expandKey(key) {
        var nk = key.length / 4;            // 4, 6 or 8
        var nr = nk + 6;                    // rounds
        var w = [];
        for (var i = 0; i < nk; i++) {
            w[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
        }
        for (var j = nk; j < 4 * (nr + 1); j++) {
            var t = w[j - 1];
            if (j % nk === 0) {
                // RotWord
                t = ((t << 8) | (t >>> 24)) & 0xffffffff;
                // SubWord
                t = ((SBOX[(t >>> 24) & 0xff] << 24) |
                     (SBOX[(t >>> 16) & 0xff] << 16) |
                     (SBOX[(t >>> 8) & 0xff] << 8) |
                     SBOX[t & 0xff]) & 0xffffffff;
                t = (t ^ (RCON[j / nk - 1] << 24)) & 0xffffffff;
            } else if (nk > 6 && j % nk === 4) {
                t = ((SBOX[(t >>> 24) & 0xff] << 24) |
                     (SBOX[(t >>> 16) & 0xff] << 16) |
                     (SBOX[(t >>> 8) & 0xff] << 8) |
                     SBOX[t & 0xff]) & 0xffffffff;
            }
            w[j] = (w[j - nk] ^ t) & 0xffffffff;
        }
        return { w: w, nr: nr };
    }

    // ── AES single-block decrypt (state = 16 bytes, column-major) ─────────
    function decryptBlock(state, ctx) {
        var w = ctx.w, nr = ctx.nr;

        function addRoundKey(round) {
            for (var c = 0; c < 4; c++) {
                var word = w[round * 4 + c];
                for (var r = 0; r < 4; r++) {
                    state[r + 4 * c] ^= (word >>> (24 - 8 * r)) & 0xff;
                }
            }
        }

        function invSubBytes() {
            for (var k = 0; k < 16; k++) state[k] = INV_SBOX[state[k]];
        }

        // row r rotated right by r
        function invShiftRows() {
            var t;
            // row 1: rotate right by 1
            t = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = t;
            // row 2: rotate right by 2
            t = state[2]; state[2] = state[10]; state[10] = state[2];
            t = state[14]; state[14] = state[6]; state[6] = state[14];
            // row 3: rotate right by 3 (= rotate left by 1)
            t = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = t;
        }

        function invMixColumns() {
            for (var c = 0; c < 4; c++) {
                var i0 = c * 4, a0 = state[i0], a1 = state[i0 + 1], a2 = state[i0 + 2], a3 = state[i0 + 3];
                state[i0]     = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
                state[i0 + 1] = gmul(a0, 9)  ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
                state[i0 + 2] = gmul(a0, 13) ^ gmul(a1, 9)  ^ gmul(a2, 14) ^ gmul(a3, 11);
                state[i0 + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9)  ^ gmul(a3, 14);
            }
        }

        addRoundKey(nr);
        for (var round = nr - 1; round >= 1; round--) {
            invShiftRows();
            invSubBytes();
            addRoundKey(round);
            invMixColumns();
        }
        invShiftRows();
        invSubBytes();
        addRoundKey(0);
        return state;
    }

    // ── AES-256-CBC decrypt, PKCS7 unpad. data/key/iv are byte arrays ──────
    function aesCbcDecrypt(data, key, iv) {
        if (data.length === 0 || data.length % 16 !== 0) return null;
        var ctx = expandKey(key);
        var out = [];
        var prev = iv;
        for (var off = 0; off < data.length; off += 16) {
            var block = data.slice(off, off + 16);
            var dec = decryptBlock(block.slice(), ctx);
            var plain = [];
            for (var i = 0; i < 16; i++) plain.push(dec[i] ^ prev[i]);
            prev = block;
            out = out.concat(plain);
        }
        // PKCS7 unpad
        if (out.length === 0) return null;
        var pad = out[out.length - 1];
        if (pad < 1 || pad > 16 || pad > out.length) return null;
        for (var p = out.length - pad; p < out.length; p++) {
            if (out[p] !== pad) return null;
        }
        return out.slice(0, out.length - pad);
    }

    // ── SHA-256 ────────────────────────────────────────────────────────────
    var K256 = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];

    function sha256Bytes(data) {
        var H = [
            0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
            0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
        ];
        var msg = data.slice();
        var bitLen = data.length * 8;
        msg.push(0x80);
        while (msg.length % 64 !== 56) msg.push(0);
        // 64-bit length (assume < 2^32 bits)
        msg.push(0); msg.push(0); msg.push(0); msg.push(0);
        msg.push((bitLen / 0x100000000) & 0xff);
        msg.push((bitLen >>> 24) & 0xff);
        msg.push((bitLen >>> 16) & 0xff);
        msg.push((bitLen >>> 8) & 0xff);
        msg.push(bitLen & 0xff);

        function rotr(x, n) { return ((x >>> n) | (x << (32 - n))) & 0xffffffff; }

        for (var blk = 0; blk < msg.length; blk += 64) {
            var W = [];
            for (var t = 0; t < 16; t++) {
                var o = blk + t * 4;
                W[t] = (msg[o] << 24) | (msg[o + 1] << 16) | (msg[o + 2] << 8) | msg[o + 3];
            }
            for (var t2 = 16; t2 < 64; t2++) {
                var s0 = rotr(W[t2 - 15], 7) ^ rotr(W[t2 - 15], 18) ^ (W[t2 - 15] >>> 3);
                var s1 = rotr(W[t2 - 2], 17) ^ rotr(W[t2 - 2], 19) ^ (W[t2 - 2] >>> 10);
                W[t2] = ((W[t2 - 16] + s0 + W[t2 - 7] + s1) & 0xffffffff) >>> 0;
            }
            var a = H[0], b = H[1], c = H[2], d = H[3];
            var e = H[4], f = H[5], g = H[6], h = H[7];
            for (var j = 0; j < 64; j++) {
                var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                var ch = (e & f) ^ (~e & g);
                var temp1 = (h + S1 + ch + K256[j] + W[j]) & 0xffffffff;
                var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                var maj = (a & b) ^ (a & c) ^ (b & c);
                var temp2 = (S0 + maj) & 0xffffffff;
                h = g; g = f; f = e;
                e = (d + temp1) & 0xffffffff;
                d = c; c = b; b = a;
                a = (temp1 + temp2) & 0xffffffff;
            }
            H[0] = (H[0] + a) & 0xffffffff; H[1] = (H[1] + b) & 0xffffffff;
            H[2] = (H[2] + c) & 0xffffffff; H[3] = (H[3] + d) & 0xffffffff;
            H[4] = (H[4] + e) & 0xffffffff; H[5] = (H[5] + f) & 0xffffffff;
            H[6] = (H[6] + g) & 0xffffffff; H[7] = (H[7] + h) & 0xffffffff;
        }
        var out = [];
        for (var q = 0; q < 8; q++) {
            out.push((H[q] >>> 24) & 0xff, (H[q] >>> 16) & 0xff, (H[q] >>> 8) & 0xff, H[q] & 0xff);
        }
        return out;
    }

    // ── HMAC-SHA256 (key < 64 bytes, our use case) ──────────────────────────
    function hmacSha256(keyBytes, msgBytes) {
        var k = keyBytes.slice();
        while (k.length < 64) k.push(0);
        var ipad = [], opad = [];
        for (var i = 0; i < 64; i++) {
            ipad.push(k[i] ^ 0x36);
            opad.push(k[i] ^ 0x5c);
        }
        var inner = sha256Bytes(ipad.concat(msgBytes));
        return sha256Bytes(opad.concat(inner));
    }

    // ── Base64 ──────────────────────────────────────────────────────────────
    var B64C = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var B64MAP = {};
    for (var b = 0; b < 64; b++) B64MAP[B64C.charAt(b)] = b;
    B64MAP["-"] = 62; // url-safe
    B64MAP["_"] = 63;

    function b64Decode(str) {
        var s = String(str).replace(/[^A-Za-z0-9+/_-]/g, "");
        var out = [], bits = 0, acc = 0;
        for (var i = 0; i < s.length; i++) {
            var v = B64MAP[s.charAt(i)];
            if (v === undefined) continue;
            acc = (acc << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.push((acc >>> bits) & 0xff);
            }
        }
        return out;
    }

    function b64Encode(bytes, urlSafe) {
        var s = "", bits = 0, acc = 0;
        for (var i = 0; i < bytes.length; i++) {
            acc = (acc << 8) | bytes[i];
            bits += 8;
            while (bits >= 6) {
                bits -= 6;
                s += B64C.charAt((acc >>> bits) & 0x3f);
            }
        }
        if (bits > 0) s += B64C.charAt((acc << (6 - bits)) & 0x3f);
        if (urlSafe) s = s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
        return s;
    }

    // ── UTF-8 helpers ───────────────────────────────────────────────────────
    function utf8Encode(str) {
        var out = [];
        str = String(str);
        for (var i = 0; i < str.length; i++) {
            var c = str.charCodeAt(i);
            if (c < 0x80) out.push(c);
            else if (c < 0x800) {
                out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
            } else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
                // surrogate pair
                var c2 = str.charCodeAt(i + 1);
                var cp = 0x10000 + ((c & 0x3ff) << 10) + (c2 & 0x3ff);
                out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f),
                         0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
                i++;
            } else {
                out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
            }
        }
        return out;
    }

    function utf8Decode(bytes) {
        var s = "";
        for (var i = 0; i < bytes.length; ) {
            var b = bytes[i];
            if (b < 0x80) { s += String.fromCharCode(b); i++; }
            else if (b < 0xe0) {
                s += String.fromCharCode(((b & 0x1f) << 6) | (bytes[i + 1] & 0x3f)); i += 2;
            } else if (b < 0xf0) {
                s += String.fromCharCode(((b & 0x0f) << 12) | ((bytes[i + 1] & 0x3f) << 6) | (bytes[i + 2] & 0x3f)); i += 3;
            } else {
                var cp = ((b & 0x07) << 18) | ((bytes[i + 1] & 0x3f) << 12) | ((bytes[i + 2] & 0x3f) << 6) | (bytes[i + 3] & 0x3f);
                cp -= 0x10000;
                s += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff)); i += 4;
            }
        }
        return s;
    }

    return {
        aesCbcDecrypt: aesCbcDecrypt,
        hmacSha256: hmacSha256,
        b64Decode: b64Decode,
        b64Encode: b64Encode,
        utf8Encode: utf8Encode,
        utf8Decode: utf8Decode
    };
})();

// ══════════════════════════════════════════════════════════════════════════

class DefaultExtension extends MProvider {
    constructor() {
        super();
        this.client = new Client();
    }

    get ua() {
        return "Mozilla/5.0 (Bindoj NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
    }

    get headers() {
        return {
            "User-Agent": this.ua,
            "Referer": this.source.baseUrl + "/",
        };
    }

    get ajaxHeaders() {
        return {
            "User-Agent": this.ua,
            "Referer": this.source.baseUrl + "/",
            "X-Requested-With": "XMLHttpRequest",
        };
    }

    abs(path) {
        if (!path) return "";
        if (path.indexOf("http") === 0) return path;
        return this.source.baseUrl + (path.charAt(0) === "/" ? path : "/" + path);
    }

    async fetchDoc(path, headers) {
        var res = await this.client.get(this.abs(path), headers || this.headers);
        return new Document(res.body);
    }

    async fetchAjax(path) {
        var res = await this.client.get(this.abs(path), this.ajaxHeaders);
        var json = JSON.parse(res.body);
        if (!json || json.status !== 200) throw new Error("ajax failed: " + path);
        return json.result;
    }

    // ── Browse ────────────────────────────────────────────────────────────────

    parseList(doc) {
        var list = [];
        var items = doc.select("#list-items .item");
        for (var i = 0; i < items.length; i++) {
            var item = items[i];
            var anchor = item.selectFirst("a.name.d-title") || item.selectFirst(".poster a");
            if (!anchor) continue;
            var href = anchor.attr("href");
            if (!href) continue;

            var name = (anchor.text || "").trim();
            var img = item.selectFirst("img");
            if (!name && img) {
                name = (img.attr("alt") || "").trim();
            }
            if (!name) continue;

            list.push({
                name: name,
                link: this.abs(href).replace(/\/ep-[^/?#]+$/, ""),
                imageUrl: img ? (img.attr("src") || "") : "",
            });
        }
        return list;
    }

    hasNextPage(doc, page) {
        var links = doc.select(".pagination a.page-link");
        var max = 0;
        for (var i = 0; i < links.length; i++) {
            var href = links[i].attr("href") || "";
            var m = href.match(/[?&]page=(\d+)/);
            if (m) {
                var n = parseInt(m[1], 10);
                if (n > max) max = n;
            }
        }
        return max > page;
    }

    async filterPage(query, page) {
        var sep = query ? "&" : "";
        var doc = await this.fetchDoc("/filter?" + query + sep + "page=" + page);
        var list = this.parseList(doc);
        return { list: list, hasNextPage: this.hasNextPage(doc, page) };
    }

    async getPopular(page) {
        return await this.filterPage("sort_by=m_view", page);
    }

    async getLatestUpdates(page) {
        return await this.filterPage("sort_by=last_updated", page);
    }

    async search(query, page, filters) {
        var parts = [];
        if (query) parts.push("keyword=" + encodeURIComponent(query));
        return await this.filterPage(parts.join("&"), page);
    }

    // ── Detail ────────────────────────────────────────────────────────────────

    statusCode(text) {
        var s = (text || "").toLowerCase();
        if (s.indexOf("finished") >= 0 || s.indexOf("completed") >= 0) return 1;
        if (s.indexOf("releasing") >= 0 || s.indexOf("airing") >= 0 || s.indexOf("ongoing") >= 0) return 0;
        if (s.indexOf("not yet") >= 0 || s.indexOf("upcoming") >= 0) return 4;
        return 5;
    }

    async parseEpisodes(animeId, detailUrl) {
        var html = await this.fetchAjax("/ajax/episode/list/" + animeId);
        var doc = new Document(html);
        var chapters = [];

        var slugMatch = String(detailUrl).match(/\/watch\/([^/?#]+)/);
        var slug = slugMatch ? slugMatch[1] : "x";

        var lis = doc.select(".episodes li");

        for (var i = 0; i < lis.length; i++) {
            var li = lis[i];
            var a = li.selectFirst("a");
            if (!a) continue;

            var ids = a.attr("data-ids");
            if (!ids) continue;

            var num = a.attr("data-num") || "";
            var titleEl = a.selectFirst(".d-title");
            var title = titleEl ? (titleEl.text || "").trim() : (li.attr("title") || "").trim();
            if (/^Episode\s+\d+$/i.test(title)) title = "";

            var name = "E" + num + (title ? ": " + title : "");

            var hasSub = a.attr("data-sub") === "1";
            var hasDub = a.attr("data-dub") === "1";
            var badge = hasSub && hasDub ? "Sub | Dub" : hasDub ? "Dub" : hasSub ? "Sub" : "";

            var dateUpload = null;
            var ts = a.attr("data-timestamp");
            if (ts) {
                var n = parseInt(ts, 10);
                if (!isNaN(n)) dateUpload = String(n * 1000);
            }

            chapters.push({
                name: name,
                url: this.abs("/watch/" + slug + "/ep-" + num) + "?aw_ids=" + encodeURIComponent(ids),
                scanlator: badge,
                dateUpload: dateUpload,
            });
        }

        return chapters.reverse();
    }

    async getDetail(url) {
        var doc = await this.fetchDoc(url);

        var poster = doc.selectFirst(".ani.poster[data-tip]");
        var animeId = poster ? poster.attr("data-tip") : null;
        if (!animeId) {
            var fav = doc.selectFirst(".ctrl.favourite[data-id]");
            if (fav) animeId = fav.attr("data-id");
        }
        if (!animeId) throw new Error("Could not determine anime id from " + url);

        var details = { link: this.abs(url) };

        var titleEl = doc.selectFirst("#w-info h1.title");
        if (titleEl) details.name = (titleEl.text || "").trim();

        var img = doc.selectFirst("#w-info .binfo .poster img");
        if (img) details.imageUrl = img.attr("src") || "";
        if (!details.imageUrl) {
            var og = doc.selectFirst("meta[property='og:image']");
            if (og) details.imageUrl = og.attr("content") || "";
        }

        var desc = doc.selectFirst("#w-info .synopsis .content");
        details.description = desc ? (desc.text || "").trim() : "";

        var genre = [];
        var seen = {};
        var genreLinks = doc.select("#w-info .bmeta .meta a[href*='/genre/']");
        for (var i = 0; i < genreLinks.length; i++) {
            var g = (genreLinks[i].text || "").trim();
            if (g && !seen[g.toLowerCase()]) {
                seen[g.toLowerCase()] = true;
                genre.push(g);
            }
        }
        details.genre = genre;

        details.status = 5;
        var metaRows = doc.select("#w-info .bmeta .meta div");
        for (var r = 0; r < metaRows.length; r++) {
            var rowText = (metaRows[r].text || "").trim();
            if (/^Status\s*:/i.test(rowText)) {
                details.status = this.statusCode(rowText);
                break;
            }
        }

        details.chapters = await this.parseEpisodes(animeId, url);
        return details;
    }

    // ── Playback ──────────────────────────────────────────────────────────────

    audioLabel(type) {
        return { sub: "Sub", dub: "Dub" }[type] || String(type).toUpperCase();
    }

    // ── MegaPlay decryption + token signing (V10) ────────────────────────────
    // MegaPlay now returns the m3u8 URL AES-256-CBC-encrypted in "enc", and
    // the CDN requires a signed token on the m3u8 URL. Mirrors the behaviour
    // of the Anikoto/Aniyomi extractor: decrypt enc -> extract "file" -> if no
    // token present, generate HMAC-SHA256 signed one (valid 90 seconds).
    processMegaplaySource(enc, fallbackSource) {
        var m3u8 = null;
        var wasDecrypted = false;

        if (enc && String(enc).length > 0) {
            try {
                var keyStr = "i?LMTAx0Q6,:}50U";
                var keyBytes = MegaCrypto.utf8Encode(keyStr);
                // pad with zero bytes to 32 (= AES-256), like the Kotlin
                // extractor does with ByteArray(32)
                while (keyBytes.length < 32) keyBytes.push(0);

                var ivBytes = MegaCrypto.utf8Encode("W0;27ToaUpl_P%'c");

                var cipherBytes = MegaCrypto.b64Decode(enc);

                if (cipherBytes.length > 0 && cipherBytes.length % 16 === 0) {
                    var plain = MegaCrypto.aesCbcDecrypt(cipherBytes, keyBytes, ivBytes);
                    if (plain) {
                        var json = MegaCrypto.utf8Decode(plain);
                        var m = json.match(/"file"\s*:\s*"([^"]+)"/);
                        if (m) {
                            m3u8 = m[1];
                            wasDecrypted = true;
                        }
                    }
                }
            } catch (e) {
                // decryption failed -> fall back to plain source below
            }
        }

        if (!m3u8 && fallbackSource) m3u8 = fallbackSource;
        if (!m3u8) return null;

        // Already has a token, or wasn't an encrypted link -> use as-is
        if (!wasDecrypted || /[?&]token=/i.test(m3u8)) return m3u8;

        // Extract the two 32-hex path segments for the signing payload
        var pm = m3u8.match(/\/([a-f0-9]{32})\/([a-f0-9]{32})\//i);
        if (!pm) return m3u8;

        var pathKey = pm[1].toLowerCase() + "/" + pm[2].toLowerCase();
        var expiry = Math.floor(Date.now() / 1000) + 90;
        var payload = expiry + "|" + pathKey;

        var payloadBytes = MegaCrypto.utf8Encode(payload);
        var sigBytes = MegaCrypto.hmacSha256(
            MegaCrypto.utf8Encode("MpCdnT0k3n!9f2K#xQ7vL5mR8wN1pY4s"),
            payloadBytes
        );

        var token =
            MegaCrypto.b64Encode(payloadBytes, true) +
            "." +
            MegaCrypto.b64Encode(sigBytes, true);

        return m3u8 + (m3u8.indexOf("?") >= 0 ? "&" : "?") + "token=" + encodeURIComponent(token);
    }

    async extractMegaplay(embedUrl, label, type) {
        var res = await this.client.get(embedUrl, {
            "User-Agent": this.ua,
            "Referer": this.source.baseUrl + "/",
        });
        var html = res.body || "";
        var m = html.match(/id="megaplay-player"[\s\S]{0,200}?data-id="(\d+)"/);
        if (!m) return [];
        var mediaId = m[1];

        var origin = (embedUrl.match(/^(https?:\/\/[^/]+)/) || [])[1];
        if (!origin) return [];

        var srcHeaders = {
            "User-Agent": this.ua,
            "Referer": embedUrl,
            "X-Requested-With": "XMLHttpRequest",
        };
        var typeParam = "&type=" + encodeURIComponent(type || "sub");

        var json = null;
        try {
            var srcRes = await this.client.get(
                origin + "/stream/getSourcesNew?id=" + mediaId + typeParam,
                srcHeaders
            );
            json = JSON.parse(srcRes.body);
        } catch (e) {
            json = null;
        }

        // Fallback to the old endpoint if getSourcesNew didn't pan out
        if (!json || (!json.enc && !json.sources)) {
            try {
                var srcRes2 = await this.client.get(
                    origin + "/stream/getSources?id=" + mediaId,
                    srcHeaders
                );
                var json2 = JSON.parse(srcRes2.body);
                if (json2 && (json2.enc || json2.sources)) json = json2;
            } catch (e) {
                // keep whatever json (or null) we already had
            }
        }

        if (!json) return [];

        // The m3u8 is either encrypted in "enc" or (legacy) in "sources"
        // (which may be a plain string or {file:"..."}).
        var fallback = null;
        if (json.sources) {
            if (typeof json.sources === "string") fallback = json.sources;
            else if (json.sources.file) fallback = json.sources.file;
        }
        var file = this.processMegaplaySource(json.enc, fallback);
        if (!file) return [];

        var introOutro = null;
        var rawIntro = json.intro;
        var rawOutro = json.outro;
        var hasIntro = rawIntro && (rawIntro.start || rawIntro.end);
        var hasOutro = rawOutro && (rawOutro.start || rawOutro.end);
        if (hasIntro || hasOutro) {
            introOutro = {
                intro: hasIntro ? { start: rawIntro.start, end: rawIntro.end } : null,
                outro: hasOutro ? { start: rawOutro.start, end: rawOutro.end } : null,
            };
        }

        var streams = [
            {
                url: file,
                originalUrl: file,
                quality: label,
                headers: { "User-Agent": this.ua, "Referer": origin + "/" },
            },
        ];

        if (introOutro) {
            if (introOutro.intro) streams[0].intro = introOutro.intro;
            if (introOutro.outro) streams[0].outro = introOutro.outro;
        }

        if (json.tracks && json.tracks.length) {
            var subs = [];
            for (var t = 0; t < json.tracks.length; t++) {
                var tr = json.tracks[t];
                if (tr && tr.file && (tr.kind === "captions" || tr.kind === "subtitles")) {
                    subs.push({ file: tr.file, label: tr.label || "Unknown" });
                }
            }
            if (subs.length) streams[0].subtitles = subs;
        }

        return streams;
    }

    async getVideoList(url) {
        var m = String(url).match(/[?&]aw_ids=([^&#]+)/);
        if (!m) throw new Error("Unrecognised episode URL: " + url);
        var ids = decodeURIComponent(m[1]);

        var html = await this.fetchAjax("/ajax/server/list?servers=" + encodeURIComponent(ids));
        var doc = new Document(html);

        var types = doc.select(".servers .type");
        var jobs = [];
        for (var t = 0; t < types.length; t++) {
            var type = types[t].attr("data-type") || "";
            var lis = types[t].select("li[data-link-id]");
            for (var i = 0; i < lis.length; i++) {
                jobs.push({
                    type: type,
                    linkId: lis[i].attr("data-link-id"),
                    server: (lis[i].text || "").trim(),
                });
            }
        }

        var self = this;
        var results = await Promise.all(
            jobs.map(async function (job) {
                try {
                    var res = await self.fetchAjax("/ajax/server?get=" + encodeURIComponent(job.linkId));
                    var embedUrl = res ? res.url : null;
                    if (!embedUrl) return [];
                    var label = job.server + " [" + self.audioLabel(job.type) + "]";
                    var out = await self.extractMegaplay(embedUrl, label, job.type);

                    for (var s = 0; s < out.length; s++) out[s].audio = job.type;
                    return out;
                } catch (e) {
                    // surface the real failure per-server instead of silently
                    // dropping it
                    return [
                        {
                            url: "",
                            originalUrl: "",
                            quality: "[ERROR] " + job.server + " (" + job.type + "): " + (e && e.message ? e.message : String(e)),
                            headers: {},
                            audio: job.type,
                            __debugError: true,
                        },
                    ];
                }
            })
        );

        var streams = [];
        for (var r = 0; r < results.length; r++) streams = streams.concat(results[r]);
        if (streams.length === 0) throw new Error("No playable stream found for this episode");

        // Borrow intro/outro across servers within the same audio track
        var borrowedByAudio = {};
        for (var b = 0; b < streams.length; b++) {
            var bs = streams[b];
            var audioKey = bs.audio || "sub";
            if (!borrowedByAudio[audioKey]) borrowedByAudio[audioKey] = {};
            if (bs.intro && !borrowedByAudio[audioKey].intro) borrowedByAudio[audioKey].intro = bs.intro;
            if (bs.outro && !borrowedByAudio[audioKey].outro) borrowedByAudio[audioKey].outro = bs.outro;
        }
        for (var p = 0; p < streams.length; p++) {
            var ps = streams[p];
            var pAudioKey = ps.audio || "sub";
            var borrowed = borrowedByAudio[pAudioKey];
            if (!borrowed) continue;
            if (!ps.intro && borrowed.intro) ps.intro = borrowed.intro;
            if (!ps.outro && borrowed.outro) ps.outro = borrowed.outro;
        }

        streams = streams
            .map(function (s, idx) {
                return { s: s, idx: idx, isVidplay: /vidplay/i.test(s.quality || "") };
            })
            .sort(function (a, b) {
                if (a.isVidplay === b.isVidplay) return a.idx - b.idx;
                return a.isVidplay ? -1 : 1;
            })
            .map(function (w) {
                return w.s;
            });

        return streams.map(function (s) {
            var out = {
                url: s.url,
                originalUrl: s.originalUrl || s.url,
                quality: s.quality || "Default",
                headers: s.headers || {},
                audio: s.audio || "sub",
            };
            if (s.subtitles) out.subtitles = s.subtitles;
            if (s.intro) out.intro = s.intro;
            if (s.outro) out.outro = s.outro;
            return out;
        });
    }

    // ── Filters ─────────────────────────────────────────────────────────────

    getFilterList() {
        return [];
    }

    getSourcePreferences() {
        return [];
    }
}
