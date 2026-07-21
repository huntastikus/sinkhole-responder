"use strict";

const toastTimers = new WeakMap();

export function readCookie(name) {
  for (const item of String(document.cookie || "").split(";")) {
    const [cookieName, ...value] = item.trim().split("=");
    if (cookieName === name) {
      const encoded = value.join("=");
      try {
        return decodeURIComponent(encoded);
      } catch {
        return encoded;
      }
    }
  }
  return "";
}

export class APIError extends Error {
  constructor(status, body, fallback) {
    super(body?.error || fallback);
    this.status = status;
    this.body = body;
  }
}

export class SessionExpiredError extends Error {}

export async function requestJSON(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");
  if (method !== "GET" && method !== "HEAD") {
    headers.set("X-CSRF-Token", readCookie("sr_csrf"));
  }
  if (options.body !== undefined && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(path, { ...options, method, headers });
  const contentType = response.headers.get("content-type") || "";
  if (response.redirected || !contentType.toLowerCase().includes("application/json")) {
    throw new SessionExpiredError("Session expired — reload to sign in again.");
  }

  let body;
  try {
    body = await response.json();
  } catch {
    throw new APIError(response.status, null, "The server returned an invalid response.");
  }
  if (!response.ok) {
    throw new APIError(response.status, body, "The request failed.");
  }
  return body;
}

export function showBanner(element, message) {
  const messageElement = element.querySelector?.("[data-banner-message]") || element;
  messageElement.textContent = message;
  element.hidden = false;
}

export function hideBanner(element) {
  element.hidden = true;
}

export function showToast(element, message, timeoutMs = 4500) {
  window.clearTimeout(toastTimers.get(element));
  element.textContent = message;
  element.hidden = false;
  toastTimers.set(element, window.setTimeout(() => {
    element.hidden = true;
    toastTimers.delete(element);
  }, timeoutMs));
}

export function setBusy(button, busy, busyLabel) {
  if (busy) {
    button.dataset.label = button.textContent;
    button.textContent = busyLabel;
  } else if (button.dataset.label) {
    button.textContent = button.dataset.label;
    delete button.dataset.label;
  }
  button.disabled = busy;
}

export function textElement(tag, text, className) {
  const element = document.createElement(tag);
  if (className) {
    element.className = className;
  }
  element.textContent = text;
  return element;
}
