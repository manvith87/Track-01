/**
 * Small, non-secret browser preferences.
 *
 * Only the last repository URL is remembered (sessionStorage, cleared with the
 * tab). No token, approval secret or analysis content is ever stored here.
 */

const REPOSITORY_URL_KEY = "blastradius.screen-a.last-repository-url";

export function loadLastRepositoryUrl(): string {
  try {
    return window.sessionStorage.getItem(REPOSITORY_URL_KEY) ?? "";
  } catch {
    return "";
  }
}

export function saveLastRepositoryUrl(url: string): void {
  try {
    if (url.trim()) {
      window.sessionStorage.setItem(REPOSITORY_URL_KEY, url.trim());
    }
  } catch {
    // Storage can be disabled; remembering the URL is a convenience only.
  }
}
