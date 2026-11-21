// Apply the saved theme preference before first paint. CSS handles the OS default.
(function () {
  const root = document.documentElement;
  root.classList.add("js");
  const COOKIE = "uvy-theme";

  function readCookie() {
    try {
      const m = document.cookie.match(/(?:^|; )uvy-theme=([^;]*)/);
      const val = m ? decodeURIComponent(m[1]) : null;
      return val === "light" || val === "dark" ? val : null;
    } catch (_) {
      return null;
    }
  }
  function readSaved() {
    const fromCookie = readCookie();
    if (fromCookie) return fromCookie;
    try {
      const val = localStorage.getItem(COOKIE);
      return val === "light" || val === "dark" ? val : null;
    } catch (_) {
      return null;
    }
  }
  function writeSaved(value) {
    try {
      document.cookie =
        COOKIE +
        "=" +
        encodeURIComponent(value) +
        "; path=/; max-age=31536000; SameSite=Lax";
    } catch (_) {}
    try {
      localStorage.setItem(COOKIE, value);
    } catch (_) {}
  }

  // Forced-theme specimens (light.html / dark.html) stay locked without overwriting the cookie.
  const forced = root.dataset.exampleTheme;
  if (forced === "light" || forced === "dark") {
    root.dataset.theme = forced;
  } else {
    const saved = readSaved();
    if (saved) root.dataset.theme = saved;
  }

  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-enable-with-js]").forEach((control) => {
      control.disabled = false;
    });
    document.querySelectorAll("[data-requires-js]").forEach((control) => {
      control.hidden = false;
    });

    const system = matchMedia("(prefers-color-scheme: dark)");
    const theme = document.getElementById("theme");
    function updateTheme() {
      const dark = root.dataset.theme
        ? root.dataset.theme === "dark"
        : system.matches;
      theme.setAttribute(
        "aria-label",
        dark ? "Switch to light theme" : "Switch to dark theme",
      );
      theme.title = theme.getAttribute("aria-label");
      theme.querySelector("[data-icon=moon]").toggleAttribute("hidden", dark);
      theme.querySelector("[data-icon=sun]").toggleAttribute("hidden", !dark);
    }
    if (theme) {
      theme.hidden = false;
      updateTheme();
      theme.addEventListener("click", function () {
        const dark = root.dataset.theme
          ? root.dataset.theme === "dark"
          : system.matches;
        const next = dark ? "light" : "dark";
        root.dataset.theme = next;
        if (!forced) writeSaved(next);
        updateTheme();
      });
      system.addEventListener("change", updateTheme);
      window.addEventListener("storage", function (event) {
        if (!forced && event.key === COOKIE) {
          if (event.newValue === "light" || event.newValue === "dark")
            root.dataset.theme = event.newValue;
          updateTheme();
        }
      });
    }

    // Copy buttons: copy text from [data-copy-target] or [data-copy-text].
    document
      .querySelectorAll("[data-copy-target], [data-copy-text]")
      .forEach((button) => {
        button.addEventListener("click", async function () {
          const targetId = button.dataset.copyTarget;
          const text = targetId
            ? (document.getElementById(targetId)?.textContent ?? "").trim()
            : button.dataset.copyText || "";
          if (!text) return;
          try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
              await navigator.clipboard.writeText(text);
            } else {
              const area = document.createElement("textarea");
              area.value = text;
              area.setAttribute("readonly", "");
              area.style.position = "fixed";
              area.style.opacity = "0";
              document.body.append(area);
              area.select();
              document.execCommand("copy");
              area.remove();
            }
          } catch (_) {}
          button.classList.add("is-copied");
          const liveId = button.dataset.copyStatus;
          if (liveId) {
            const live = document.getElementById(liveId);
            if (live) live.textContent = "Copied to clipboard.";
          }
          clearTimeout(button._copyTimer);
          button._copyTimer = setTimeout(() => {
            button.classList.remove("is-copied");
          }, 1800);
        });
      });

    // Accessible tablists: click and arrow-key navigation.
    document.querySelectorAll('[role="tablist"]').forEach((tablist) => {
      const tabs = [...tablist.querySelectorAll('[role="tab"]')];
      function selectTab(next, focus) {
        tabs.forEach((tab) => {
          const active = tab === next;
          tab.setAttribute("aria-selected", String(active));
          tab.tabIndex = active ? 0 : -1;
          const panel = document.getElementById(
            tab.getAttribute("aria-controls") || "",
          );
          if (panel) panel.hidden = !active;
        });
        if (focus) next.focus();
      }
      tabs.forEach((tab, index) => {
        tab.tabIndex = tab.getAttribute("aria-selected") === "true" ? 0 : -1;
        tab.addEventListener("click", () => selectTab(tab, false));
        tab.addEventListener("keydown", (event) => {
          let target = null;
          if (event.key === "ArrowRight")
            target = tabs[(index + 1) % tabs.length];
          else if (event.key === "ArrowLeft")
            target = tabs[(index - 1 + tabs.length) % tabs.length];
          else if (event.key === "Home") target = tabs[0];
          else if (event.key === "End") target = tabs[tabs.length - 1];
          if (target) {
            event.preventDefault();
            selectTab(target, true);
          }
        });
      });
    });

    const sidebar = document.getElementById("sidebar");
    if (!sidebar) return;
    const menu = document.getElementById("menu");
    const close = document.getElementById("menu-close");
    const backdrop = document.getElementById("menu-backdrop");
    const mobile = matchMedia("(max-width: 48rem)");
    const background = [
      document.querySelector(".site-header"),
      document.querySelector(".workspace"),
      document.querySelector("footer"),
    ];
    function setOpen(open, restoreFocus) {
      open = open && mobile.matches;
      sidebar.toggleAttribute("data-open", open);
      sidebar.inert = mobile.matches && !open;
      backdrop.hidden = !open;
      menu.setAttribute("aria-expanded", String(open));
      document.body.classList.toggle("drawer-open", open);
      background.forEach((element) => {
        if (element) element.inert = open;
      });
      if (open) {
        sidebar.setAttribute("role", "dialog");
        sidebar.setAttribute("aria-modal", "true");
        close.focus();
      } else {
        sidebar.removeAttribute("role");
        sidebar.removeAttribute("aria-modal");
        if (restoreFocus) menu.focus();
      }
    }
    menu.hidden = false;
    close.hidden = false;
    menu.addEventListener("click", () => setOpen(true, false));
    close.addEventListener("click", () => setOpen(false, true));
    backdrop.addEventListener("click", () => setOpen(false, true));
    function selectLocalSection() {
      const links = [...sidebar.querySelectorAll('nav a[href^="#"]')];
      if (!links.length) return;
      const current =
        links.find((link) => link.getAttribute("href") === location.hash) ||
        links[0];
      links.forEach((link) => {
        if (link === current) link.setAttribute("aria-current", "location");
        else link.removeAttribute("aria-current");
      });
    }
    selectLocalSection();
    window.addEventListener("hashchange", selectLocalSection);
    sidebar.addEventListener("click", (event) => {
      if (event.target.closest("a") && mobile.matches) setOpen(false, true);
    });
    sidebar.addEventListener("keydown", (event) => {
      if (!sidebar.hasAttribute("data-open")) return;
      if (event.key === "Escape") {
        event.preventDefault();
        setOpen(false, true);
      }
      if (event.key === "Tab") {
        const targets = [
          ...sidebar.querySelectorAll(
            'a[href],button,input,select,[tabindex="0"]',
          ),
        ].filter(
          (element) =>
            !element.hidden &&
            element.getClientRects().length &&
            !element.disabled,
        );
        const first = targets[0],
          last = targets[targets.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    });
    mobile.addEventListener("change", () => {
      const active = document.activeElement;
      const inside = sidebar.contains(active);
      setOpen(false, false);
      if (mobile.matches && inside) menu.focus();
      else if (!mobile.matches && (active === menu || active === close))
        theme.focus();
    });
    setOpen(false, false);
    const search = document.getElementById("nav-search");
    if (search) {
      search.closest(".nav-filters").hidden = false;
      search.addEventListener("input", function () {
        let count = 0;
        sidebar.querySelectorAll("nav a").forEach((link) => {
          link.hidden = !link.textContent
            .toLowerCase()
            .includes(search.value.trim().toLowerCase());
          if (!link.hidden) count++;
        });
        document.getElementById("nav-empty").hidden = count > 0;
      });
    }
  });
})();
