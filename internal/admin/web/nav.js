"use strict";

import { readCookie } from "./api.js";

// note: CSP prevents an inline head script, so a stored theme may briefly flash before this module loads.

const navigationLinks = [
  ["Dashboard", "/"],
  ["Configuration", "/config"],
  ["Rules", "/rules"],
  ["Rulepacks", "/rulepacks"],
  ["Certificates", "/tls"],
  ["Tools", "/tools"],
  ["Detector", "/tools/detector"],
  ["Logs", "/logs"],
  ["Setup wizard", "/wizard"],
  ["Help →", "/help/"],
];

function storedTheme() {
  try {
    const theme = window.localStorage.getItem("sr_theme");
    return theme === "light" || theme === "dark" ? theme : "";
  } catch {
    return "";
  }
}

function currentTheme() {
  const selected = document.documentElement.dataset.theme;
  if (selected === "light" || selected === "dark") {
    return selected;
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function updateThemeButton(button) {
  const theme = currentTheme();
  const next = theme === "dark" ? "light" : "dark";
  button.textContent = `Theme: ${theme === "dark" ? "Dark" : "Light"}`;
  button.setAttribute("aria-label", `Current theme: ${theme}. Switch to ${next} theme`);
}

function createLink(label, href) {
  const link = document.createElement("a");
  link.setAttribute("href", href);
  link.textContent = label;
  if (href === window.location.pathname) {
    link.classList.add("is-active");
    link.setAttribute("aria-current", "page");
  }
  return link;
}

function reloadWhenBack(status) {
  const attempt = () => {
    window
      .fetch("/login", { method: "HEAD", cache: "no-store" })
      .then(() => window.location.reload())
      .catch(() => window.setTimeout(attempt, 1500));
  };
  window.setTimeout(attempt, 2500);
  return status;
}

async function syncRestartBar(nav) {
  let pending = false;
  try {
    const response = await window.fetch("/api/system/health", {
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    if (!response.ok) {
      return;
    }
    pending = Boolean((await response.json())?.restart_pending);
  } catch {
    return;
  }
  const existing = nav.querySelector(".app-restart-bar");
  if (!pending) {
    existing?.remove();
    return;
  }
  if (existing) {
    return;
  }

  const bar = document.createElement("div");
  bar.className = "app-restart-bar";
  bar.setAttribute("role", "alert");

  const message = document.createElement("p");
  message.className = "app-restart-message";
  const strong = document.createElement("strong");
  strong.textContent = "Restart required";
  message.append(strong, " — saved changes to listeners, TLS, or limits take effect only after the responder restarts.");

  const button = document.createElement("button");
  button.className = "app-restart-button";
  button.type = "button";
  button.textContent = "Restart now";

  const status = document.createElement("span");
  status.className = "app-restart-status";

  button.addEventListener("click", async () => {
    if (!window.confirm("Restart the responder now? Active connections drop for a few seconds. It returns only if managed by Docker or systemd — a bare process would stop.")) {
      return;
    }
    button.disabled = true;
    status.textContent = "Restarting…";
    try {
      const response = await window.fetch("/api/system/restart", {
        method: "POST",
        headers: { "X-CSRF-Token": readCookie("sr_csrf") },
      });
      if (response.status === 202) {
        status.textContent = reloadWhenBack("Restarting… this page reloads when the responder returns.");
      } else if (response.status === 409) {
        status.textContent = "A restart is already in progress.";
        button.disabled = false;
      } else {
        status.textContent = (await response.text()) || "The restart could not be started.";
        button.disabled = false;
      }
    } catch {
      // The connection dropped, which is expected once the restart begins.
      status.textContent = reloadWhenBack("Restarting… this page reloads when the responder returns.");
    }
  });

  bar.append(message, button, status);
  nav.prepend(bar);
}

function main() {
  const nav = document.getElementById("app-nav");
  if (!nav) {
    return;
  }

  const selectedTheme = storedTheme();
  if (selectedTheme) {
    document.documentElement.dataset.theme = selectedTheme;
  }

  const inner = document.createElement("div");
  inner.className = "app-nav-inner";

  const brand = document.createElement("span");
  brand.className = "app-nav-brand";
  const brandLogo = document.createElement("img");
  brandLogo.className = "app-nav-logo";
  brandLogo.src = "/assets/logo.svg";
  brandLogo.alt = "";
  brandLogo.width = 34;
  brandLogo.height = 34;
  brandLogo.setAttribute("aria-hidden", "true");
  const brandName = document.createElement("span");
  brandName.textContent = "Sinkhole Responder";
  brand.append(brandLogo, brandName);

  const menuButton = document.createElement("button");
  menuButton.className = "app-nav-menu-button";
  menuButton.type = "button";
  menuButton.setAttribute("aria-expanded", "false");
  menuButton.setAttribute("aria-controls", "app-nav-panel");
  menuButton.textContent = "☰ Menu";

  const panel = document.createElement("div");
  panel.id = "app-nav-panel";
  panel.className = "app-nav-panel";

  const links = document.createElement("div");
  links.className = "app-nav-links";
  for (const [label, href] of navigationLinks) {
    links.append(createLink(label, href));
  }

  const actions = document.createElement("div");
  actions.className = "app-nav-actions";

  const themeButton = document.createElement("button");
  themeButton.className = "app-nav-action";
  themeButton.type = "button";
  updateThemeButton(themeButton);
  themeButton.addEventListener("click", () => {
    const theme = currentTheme() === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = theme;
    try {
      window.localStorage.setItem("sr_theme", theme);
    } catch {
      // The selected theme still applies for this page when storage is unavailable.
    }
    updateThemeButton(themeButton);
  });

  const logoutButton = document.createElement("button");
  logoutButton.className = "app-nav-action app-nav-logout";
  logoutButton.type = "button";
  logoutButton.textContent = "Logout";
  logoutButton.addEventListener("click", async () => {
    logoutButton.disabled = true;
    try {
      await window.fetch("/logout", {
        method: "POST",
        headers: { "X-CSRF-Token": readCookie("sr_csrf") },
      });
    } finally {
      window.location = "/login";
    }
  });

  function closeMenu() {
    panel.classList.remove("is-open");
    menuButton.setAttribute("aria-expanded", "false");
  }

  menuButton.addEventListener("click", () => {
    const open = menuButton.getAttribute("aria-expanded") !== "true";
    panel.classList.toggle("is-open", open);
    menuButton.setAttribute("aria-expanded", String(open));
  });
  inner.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeMenu();
      menuButton.focus();
    }
  });
  links.addEventListener("click", closeMenu);

  const scheme = window.matchMedia("(prefers-color-scheme: dark)");
  scheme.addEventListener("change", () => {
    if (!document.documentElement.dataset.theme) {
      updateThemeButton(themeButton);
    }
  });

  actions.append(themeButton, logoutButton);
  panel.append(links, actions);
  inner.append(brand, menuButton, panel);
  nav.append(inner);
  void syncRestartBar(nav);
  // Re-check after a save elsewhere in the app, and when the tab regains focus.
  window.addEventListener("sinkhole:restart-check", () => void syncRestartBar(nav));
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      void syncRestartBar(nav);
    }
  });
}

document.addEventListener("DOMContentLoaded", main);
