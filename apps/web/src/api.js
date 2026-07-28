/**
 * Central API helper for LICITRA dashboard.
 * Reads VITE_API_BASE and VITE_API_KEY from
 * environment variables.
 *
 * VITE_API_KEY is optional — when not set,
 * no X-API-Key header is sent (dev mode).
 */

export const BASE = import.meta.env.VITE_API_BASE
  || 'http://localhost:8000';

const API_KEY = import.meta.env.VITE_API_KEY || '';

/**
 * Build headers for API requests.
 * Always includes Content-Type for POST.
 * Adds X-API-Key only when VITE_API_KEY is set.
 */
export function apiHeaders(isPost = false) {
  const headers = {};
  if (isPost) {
    headers['Content-Type'] = 'application/json';
  }
  if (API_KEY) {
    headers['X-API-Key'] = API_KEY;
  }
  return headers;
}

/**
 * Convenience wrapper for POST requests.
 */
export async function apiPost(path, body = {}) {
  const response = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: apiHeaders(true),
    body: JSON.stringify(body),
  });
  return response;
}

/**
 * Convenience wrapper for GET requests.
 */
export async function apiGet(path) {
  const response = await fetch(`${BASE}${path}`, {
    method: 'GET',
    headers: apiHeaders(false),
  });
  return response;
}
