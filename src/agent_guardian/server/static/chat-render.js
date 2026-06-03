/* AgentGuardian — chat-bubble renderer (Markdown default, JSON when detected).
 *
 * Marker: ag.dashboard.executive.chat.render
 *
 * Progressive enhancement for the slide-over chat conversation. Each
 * ``<pre data-chat-render>`` carries the VERBATIM prompt / response text
 * (Jinja-escaped, so ``el.textContent`` is the safe raw string). On enhance:
 *
 *   - If the text parses as a JSON object/array  -> pretty-printed JSON view,
 *     pill label "JSON".
 *   - Otherwise                                  -> Markdown view (default),
 *     pill label "Markdown".
 *
 * A pill toggles between the rendered view and the raw text.
 *
 * SECURITY: the response is attacker-influenced and untrusted (a target may
 * echo ``<script>…``). This renderer NEVER assigns untrusted text to
 * innerHTML. Every node is built with createElement + textContent, and links
 * are only emitted for http(s) URLs set via setAttribute. There is therefore
 * no HTML-injection sink here.
 */
(function () {
  "use strict";

  var ENHANCED_ATTR = "data-chat-rendered";

  /* ---- JSON detection -------------------------------------------------- */
  function tryParseJson(text) {
    var t = text.trim();
    if (t.length < 2) return null;
    var first = t.charAt(0);
    var last = t.charAt(t.length - 1);
    var looksObject = first === "{" && last === "}";
    var looksArray = first === "[" && last === "]";
    if (!looksObject && !looksArray) return null;
    try {
      var parsed = JSON.parse(t);
      if (parsed && typeof parsed === "object") return parsed;
    } catch (e) {
      return null;
    }
    return null;
  }

  /* ---- Minimal, safe inline Markdown ----------------------------------- */
  // Emits text + element nodes into `parent`. Handles inline code, bold,
  // italic, and http(s) links. Unmatched markup is left as literal text.
  function renderInline(parent, text) {
    // Split on inline code first; odd indices are code spans.
    var segments = text.split("`");
    for (var s = 0; s < segments.length; s++) {
      if (s % 2 === 1) {
        var code = document.createElement("code");
        code.className = "exec-md__icode";
        code.textContent = segments[s];
        parent.appendChild(code);
      } else {
        renderInlineEmphasis(parent, segments[s]);
      }
    }
  }

  function renderInlineEmphasis(parent, text) {
    // Token scanner: links [t](url), bold **t**/__t__, italic *t*/_t_.
    var re = /(\[([^\]]+)\]\((https?:\/\/[^\s)]+)\))|(\*\*([^*]+)\*\*|__([^_]+)__)|(\*([^*]+)\*|_([^_]+)_)/;
    var rest = text;
    var guard = 0;
    while (rest && guard < 5000) {
      guard++;
      var m = re.exec(rest);
      if (!m) {
        parent.appendChild(document.createTextNode(rest));
        break;
      }
      if (m.index > 0) {
        parent.appendChild(document.createTextNode(rest.slice(0, m.index)));
      }
      if (m[1]) {
        // link: m[2]=text, m[3]=href (already constrained to http(s) by regex)
        var a = document.createElement("a");
        a.className = "exec-md__link";
        a.setAttribute("href", m[3]);
        a.setAttribute("target", "_blank");
        a.setAttribute("rel", "noopener noreferrer");
        a.textContent = m[2];
        parent.appendChild(a);
      } else if (m[4]) {
        var strong = document.createElement("strong");
        strong.textContent = m[5] || m[6] || "";
        parent.appendChild(strong);
      } else if (m[7]) {
        var em = document.createElement("em");
        em.textContent = m[8] || m[9] || "";
        parent.appendChild(em);
      }
      rest = rest.slice(m.index + m[0].length);
    }
  }

  /* ---- Block-level Markdown ------------------------------------------- */
  function renderMarkdown(text) {
    var root = document.createElement("div");
    root.className = "exec-md";
    var lines = text.split("\n");
    var i = 0;
    while (i < lines.length) {
      var line = lines[i];
      var fence = /^```/.test(line);
      if (fence) {
        var buf = [];
        i++;
        while (i < lines.length && !/^```/.test(lines[i])) {
          buf.push(lines[i]);
          i++;
        }
        i++; // skip closing fence
        var pre = document.createElement("pre");
        pre.className = "exec-md__code";
        var codeEl = document.createElement("code");
        codeEl.textContent = buf.join("\n");
        pre.appendChild(codeEl);
        root.appendChild(pre);
        continue;
      }
      var h = line.match(/^(#{1,6})\s+(.*)$/);
      if (h) {
        var hel = document.createElement(h[1].length <= 2 ? "h4" : "h5");
        hel.className = "exec-md__h";
        renderInline(hel, h[2]);
        root.appendChild(hel);
        i++;
        continue;
      }
      if (/^\s*[-*+]\s+/.test(line)) {
        var ul = document.createElement("ul");
        ul.className = "exec-md__list";
        while (i < lines.length && /^\s*[-*+]\s+/.test(lines[i])) {
          var li = document.createElement("li");
          renderInline(li, lines[i].replace(/^\s*[-*+]\s+/, ""));
          ul.appendChild(li);
          i++;
        }
        root.appendChild(ul);
        continue;
      }
      if (/^\s*\d+\.\s+/.test(line)) {
        var ol = document.createElement("ol");
        ol.className = "exec-md__list";
        while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
          var oli = document.createElement("li");
          renderInline(oli, lines[i].replace(/^\s*\d+\.\s+/, ""));
          ol.appendChild(oli);
          i++;
        }
        root.appendChild(ol);
        continue;
      }
      if (/^\s*$/.test(line)) {
        i++;
        continue;
      }
      // Paragraph: gather consecutive non-blank, non-block lines.
      var para = [line];
      i++;
      while (
        i < lines.length &&
        !/^\s*$/.test(lines[i]) &&
        !/^```/.test(lines[i]) &&
        !/^(#{1,6})\s/.test(lines[i]) &&
        !/^\s*[-*+]\s+/.test(lines[i]) &&
        !/^\s*\d+\.\s+/.test(lines[i])
      ) {
        para.push(lines[i]);
        i++;
      }
      var p = document.createElement("p");
      p.className = "exec-md__p";
      renderInline(p, para.join("\n"));
      root.appendChild(p);
    }
    return root;
  }

  function renderJson(parsed) {
    var pre = document.createElement("pre");
    pre.className = "exec-md__json";
    var code = document.createElement("code");
    code.textContent = JSON.stringify(parsed, null, 2);
    pre.appendChild(code);
    return pre;
  }

  /* ---- Enhance one bubble --------------------------------------------- */
  function enhanceOne(pre) {
    if (!pre || pre.getAttribute(ENHANCED_ATTR) === "1") return;
    var raw = pre.textContent != null ? pre.textContent : "";
    pre.setAttribute(ENHANCED_ATTR, "1");

    var placeholder = raw.trim() === "" || raw.trim() === "(no data available)";
    var parsed = placeholder ? null : tryParseJson(raw);
    var mode = parsed ? "json" : "markdown";

    // Container that replaces the raw <pre> in the layout.
    var wrap = document.createElement("div");
    wrap.className = "exec-chat__rendered";

    // Toolbar: mode pill (toggles rendered <-> raw).
    var bar = document.createElement("div");
    bar.className = "exec-chat__render-bar";
    var pill = document.createElement("button");
    pill.type = "button";
    pill.className = "exec-chat__render-pill";
    bar.appendChild(pill);

    var rendered = document.createElement("div");
    rendered.className = "exec-chat__render-view";

    var rawView = document.createElement("pre");
    rawView.className = "exec-chat__text exec-chat__raw-view";
    rawView.textContent = raw;
    rawView.style.display = "none";

    if (placeholder) {
      // Nothing to render — leave the raw text, no pill.
      rendered.appendChild(rawView);
      rawView.style.display = "";
      wrap.appendChild(rendered);
      pre.parentNode.replaceChild(wrap, pre);
      return;
    }

    if (mode === "json") {
      rendered.appendChild(renderJson(parsed));
    } else {
      rendered.appendChild(renderMarkdown(raw));
    }

    var showingRaw = false;
    function syncPill() {
      var label = mode === "json" ? "JSON" : "Markdown";
      pill.textContent = showingRaw ? "Raw" : label;
      pill.setAttribute(
        "aria-label",
        showingRaw ? "Showing raw text — click to render" : "Showing " + label + " — click for raw text"
      );
      rendered.style.display = showingRaw ? "none" : "";
      rawView.style.display = showingRaw ? "" : "none";
    }
    pill.addEventListener("click", function () {
      showingRaw = !showingRaw;
      syncPill();
    });
    syncPill();

    wrap.appendChild(bar);
    wrap.appendChild(rendered);
    wrap.appendChild(rawView);
    pre.parentNode.replaceChild(wrap, pre);
  }

  function enhance(root) {
    var scope = root || document;
    var nodes = scope.querySelectorAll("pre[data-chat-render]");
    for (var i = 0; i < nodes.length; i++) {
      try {
        enhanceOne(nodes[i]);
      } catch (e) {
        /* never let a render error break the slide-over */
      }
    }
  }

  window.AGChatRender = { enhance: enhance };

  // Enhance any server-rendered conversation present on initial load.
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      enhance(document);
    });
  } else {
    enhance(document);
  }
})();
