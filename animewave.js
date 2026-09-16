const mangayomiSources = [
    {
        "name": "AnimeWave",
        "id": 148203771,
        "lang": "en",
        "baseUrl": "https://animewave.to",
        "apiUrl": "",
        "iconUrl":
        "https://www.google.com/s2/favicons?sz=256&domain=https://animewave.to",
        "typeSource": "single",
        "itemType": 1,
        "version": "0.1.0",
        "isManga": false,
        "isNsfw": false,
        "hasCloudflare": false,
        "isFullData": false,
        "appMinVerReq": "0.5.0",
        "sourceCodeUrl":
        "https://raw.githubusercontent.com/nikolaos-messerschmidt/ShonenX_iOS/refs/heads/main/animewave.js",
        "dateFormat": "",
        "dateFormatLocale": "",
        "additionalParams": "",
        "sourceCodeLanguage": 1,
        "notes": "",
    },
];
//V9
// AnimeWave (animewave.to) — same 9anime/AniWave-family template as aniwaves.ru,
// but with a different episode/server-resolve shape and a MegaPlay-only
// player backend instead of Vidplay/DoodStream.
//
// Endpoints used (all unauthenticated ajax, server-rendered HTML otherwise):
//   /filter?...                              -> browse/search results
//   /ajax/episode/list/{animeId}             -> episode <li> list, each with
//                                                data-ids = an opaque per-
//                                                episode token (NOT a plain
//                                                numeric id like on .ru)
//   /ajax/server/list?servers={data-ids}     -> sub/dub <li data-link-id>
//   /ajax/server?get={link-id}               -> {result:{url:"<megaplay url>"}}
//   megaplay.buzz/stream/.../{ep}/{sub|dub}  -> HTML with data-id
//   megaplay.buzz/stream/getSources?id=...   -> {sources:{file:"<m3u8>"}}
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

    // #list-items .item > .inner > .ani.poster > a[href] > img[src]
    //                            > .info .b1 > a.name.d-title (English title)
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
                // /watch/{slug}/ep-N — strip the trailing episode segment so the
                // stored link always points at the detail page itself.
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

        // Real slug from the detail page URL (e.g. "danganronpa-the-animation-gwktc"),
        // so episode links point at pages that actually exist on the site rather
        // than a made-up route. Falls back to "x" only if somehow unparsable.
        var slugMatch = String(detailUrl).match(/\/watch\/([^/?#]+)/);
        var slug = slugMatch ? slugMatch[1] : "x";

        // Episodes render inside one or more <ul class="ep-range" data-range="...">
        // blocks (the site paginates in blocks of 12/24/etc for long shows); pull
        // from all of them rather than just the first, visible one.
        var lis = doc.select(".episodes li");

        for (var i = 0; i < lis.length; i++) {
            var li = lis[i];
            var a = li.selectFirst("a");
            if (!a) continue;

            // data-ids is the opaque token the server/list ajax call needs — there
            // is no plain numeric episode id on this template.
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
                // Unix seconds here, not "YYYY-MM-DD HH:MM:SS" like on .ru.
                var n = parseInt(ts, 10);
                if (!isNaN(n)) dateUpload = String(n * 1000);
            }

            chapters.push({
                name: name,
                // Real, live watch URL (this page genuinely exists and returns 200)
                // with the per-episode data-ids token riding along as a query param.
                // Using a made-up route here previously 404'd if anything in the app
                // touched/validated the URL before getVideoList ever ran.
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

        // The synopsis block on .to carries a promo/spam link as its first child
        // before the real ".content" div — only take the latter.
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

    // MegaPlay embed page -> {mediaId, realId} needed for getSources(New).
    // The page exposes them as data-id/data-realid on #megaplay-player.
    //
    // Verified live against a VidTube (vidtube.site) embed via browser
    // DevTools network trace (VidPlay-1/dub, id=747384):
    //   GET {origin}/stream/getSourcesNew?id={data-id}&type={sub|dub}
    // NOT /stream/getSources (no "New", no &type=) — that 404s. The old
    // getSources path is kept as a fallback below only in case some other
    // host (e.g. genuine megaplay.buzz) still serves the pre-"New" API;
    // if that turns out to never happen it can be deleted.
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

        // Fallback to the old endpoint if getSourcesNew didn't pan out (missing,
        // errored, or came back without a usable file) — cheap safety net in
        // case a host out there still only speaks the pre-"New" API.
        if (!json || !json.sources || !json.sources.file) {
            try {
                var srcRes2 = await this.client.get(origin + "/stream/getSources?id=" + mediaId, srcHeaders);
                var json2 = JSON.parse(srcRes2.body);
                if (json2 && json2.sources && json2.sources.file) json = json2;
            } catch (e) {
                // keep whatever json (or null) we already had
            }
        }

        var file = json && json.sources ? json.sources.file : null;
        if (!file) return [];

        // Some servers (observed: VidPlay/VidTube) return intro/outro as
        // {start:0,end:0} — i.e. no real data — while others (observed: direct
        // Megaplay) return real segment ranges for the same episode. Only treat
        // it as usable if at least one bound is non-zero; getVideoList() below
        // borrows real intro/outro from whichever server actually has it and
        // patches it onto streams whose own server didn't provide it.
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
                    // ShonenX's bridge maps these straight onto file!/label! — using
                    // different key names here leaves those null and crashes with
                    // "Null check operator used on a null value" in anime_source_adapter.dart.
                    subs.push({ file: tr.file, label: tr.label || "Unknown" });
                }
            }
            if (subs.length) streams[0].subtitles = subs;
        }

        return streams;
    }

    // VidPlay/VidTube embed page -> master.m3u8 with #EXT-X-STREAM-INF variants.
    // These hosts change domain periodically (vidtube.site, s1.akirax.buzz, etc)
    // but the embed HTML always exposes the raw m3u8 stream url inline as
    // JS/HTML — either as a /stream/{token}/{sub|dub} path we can turn into a
    // /master.m3u8, or directly via a file:/source: reference on the page.
    async extractVidplay(embedUrl, label) {
        var res = await this.client.get(embedUrl, {
            "User-Agent": this.ua,
            "Referer": this.source.baseUrl + "/",
        });
        var html = res.body || "";
        var origin = (embedUrl.match(/^(https?:\/\/[^/]+)/) || [])[1];
        if (!origin) return [];

        // Case 1: embed page IS the stream host (e.g. vidtube.site/stream/{token}/dub)
        // -> strip the trailing sub|dub segment and ask for master.m3u8 at that path.
        var streamMatch = embedUrl.match(/\/stream\/([^/?#]+)(?:\/(sub|dub))?/);
        var masterUrl = null;
        if (streamMatch) {
            masterUrl = origin + "/stream/" + streamMatch[1] + "/master.m3u8";
        }

        // Case 2: fall back to scraping any *.m3u8 reference out of the embed HTML
        // (file:/source:/hls: style JS variable, or a <source src="...">).
        if (!masterUrl) {
            var m3u8Match =
            html.match(/(?:file|source|src|hls)\s*[:=]\s*["']([^"']+\.m3u8[^"']*)["']/i) ||
            html.match(/<source[^>]+src=["']([^"']+\.m3u8[^"']*)["']/i) ||
            html.match(/https?:\/\/[^\s"'<>]+\.m3u8[^\s"'<>]*/);
            if (m3u8Match) {
                var found = m3u8Match[1] || m3u8Match[0];
                masterUrl = found.indexOf("http") === 0 ? found : origin + found;
            }
        }

        if (!masterUrl) return [];

        var vidHeaders = { "User-Agent": this.ua, "Referer": origin + "/", "Origin": origin };

        // Try to resolve the master playlist into its per-quality variants so the
        // app gets real "1080p/720p/360p" entries instead of one ambiguous file.
        try {
            var plRes = await this.client.get(masterUrl, vidHeaders);
            var body = plRes.body || "";
            if (body.indexOf("#EXT-X-STREAM-INF") >= 0) {
                var lines = body.split("\n");
                var streams = [];
                for (var i = 0; i < lines.length; i++) {
                    var line = lines[i].trim();
                    if (line.indexOf("#EXT-X-STREAM-INF") !== 0) continue;
                    var resMatch = line.match(/RESOLUTION=\d+x(\d+)/);
                    var nameMatch = line.match(/NAME="([^"]+)"/);
                    var quality = nameMatch ? nameMatch[1] : (resMatch ? resMatch[1] + "p" : "Default");
                    var variantUrl = (lines[i + 1] || "").trim();
                    if (!variantUrl || variantUrl.indexOf("#") === 0) continue;
                    var absVariant = variantUrl.indexOf("http") === 0
                    ? variantUrl
                    : masterUrl.substring(0, masterUrl.lastIndexOf("/") + 1) + variantUrl;
                    streams.push({
                        url: absVariant,
                        originalUrl: absVariant,
                        quality: label + " - " + quality,
                        headers: vidHeaders,
                    });
                }
                if (streams.length) return streams;
            }
        } catch (e) {
            // fall through to returning the master url itself below
        }

        // Master playlist fetch/parsing failed (or wasn't a variant playlist) —
        // hand back the master url directly, most players resolve it themselves.
        return [
            {
                url: masterUrl,
                originalUrl: masterUrl,
                quality: label,
                headers: vidHeaders,
            },
        ];
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
                    // All observed embed hosts (megaplay.buzz, vidtube.site/VidPlay,
                    // and presumably other rotating domains) render the SAME
                    // #megaplay-player markup with a numeric data-id, but the actual
                    // sources endpoint differs from the original megaplay.buzz guess:
                    // confirmed via browser DevTools network trace on a live VidTube
                    // (VidPlay-1/dub) embed that it's GET {origin}/stream/getSourcesNew
                    // ?id={data-id}&type={sub|dub} — not /stream/getSources (404, no
                    // "New", missing &type=). extractMegaplay() tries getSourcesNew
                    // first and falls back to the old getSources path in case some
                    // other host still needs it. A prior version of this code branched
                    // on embed hostname and guessed a separate /stream/{token}/
                    // master.m3u8 route for non-megaplay.buzz hosts — that route
                    // doesn't exist (404) and was pure speculation. Don't reintroduce
                    // that branch.
                    var label = job.server + " [" + self.audioLabel(job.type) + "]";
                    var out = await self.extractMegaplay(embedUrl, label, job.type);

                    for (var s = 0; s < out.length; s++) out[s].audio = job.type;
                    return out;
                } catch (e) {
                    // TEMP DEBUG: surface the real failure per-server instead of
                    // silently dropping it, so extraction issues are visible instead
                    // of just producing an empty stream list. Revert to `return [];`
                    // once VidPlay extraction is confirmed working.
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

        // Borrow intro/outro across servers within the same audio track: some
        // servers (observed: VidPlay/VidTube) never return real segment times,
        // while others for the exact same episode (observed: direct Megaplay)
        // do. Preferred server (e.g. VidPlay) still wins on stream URL/quality —
        // this only fills in the missing timing data, per sub/dub since intro/
        // outro can differ between audio tracks.
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

        // Prefer VidPlay as the default: stable-sort so any stream whose
        // server name contains "vidplay" comes first (within that, original
        // relative order is preserved), and tag it in the quality label so
        // apps/bridges that just show the label make the preference visible.
        // This only reorders/labels — it does not drop the other servers, so
        // Sub/Dub selection and fallbacks if VidPlay is down still work.
        streams = streams
        .map(function (s, idx) {
            return { s: s, idx: idx, isVidplay: /vidplay/i.test(s.quality || "") };
        })
        .sort(function (a, b) {
            if (a.isVidplay === b.isVidplay) return a.idx - b.idx;
            return a.isVidplay ? -1 : 1;
        })
        .map(function (w) {
            if (w.isVidplay && w.s.quality && !/\(Default\)/.test(w.s.quality)) {
                w.s.quality = w.s.quality + " (Default)";
            }
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

    // ── Filters ───────────────────────────────────────────────────────────────

    getFilterList() {
        return [];
    }

    getSourcePreferences() {
        return [];
    }
}
