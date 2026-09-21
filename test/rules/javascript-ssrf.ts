/**
 * Fixture for rules/javascript-ssrf.yaml (cortex-javascript-ssrf).
 *
 * Annotated with Semgrep's native test convention: a comment naming the rule
 * marks the line below it as an expected match, and the negated form marks a
 * line that must stay silent. See the annotations throughout this file.
 *
 * Run:  semgrep --test --config rules test/rules
 *
 * This half is the REGRESSION GUARD for the false positives that made the
 * rule unusable: receivers that are merely *spelled* like an HTTP client.
 * A real scan of a Next.js frontend produced 113 findings of which 108 were
 * MSW mock handlers exactly like the ones below.
 */

import { http, delay, HttpResponse } from 'msw';
import axios from 'axios';

// -------------------------------------------------------------------------
// MSW: `http` here declares a mock route. It never performs a request, so
// none of these may fire — the first argument is a route pattern, not a URL.
// -------------------------------------------------------------------------

const api = (p: string) => `/api${p}`;

export const handlers = [
  // ok: cortex-javascript-ssrf
  http.get(api('/users'), async ({ request }) => {
    const url = new URL(request.url);
    const page = url.searchParams.get('page');
    await delay(100);
    return HttpResponse.json({ items: [], page });
  }),

  // ok: cortex-javascript-ssrf
  http.post(api('/users'), async ({ request }) => {
    const body = await request.json();
    return HttpResponse.json(body, { status: 201 });
  }),

  // ok: cortex-javascript-ssrf
  http.get('/home/dashboard', async () => HttpResponse.json({ widgets: [] })),

  // ok: cortex-javascript-ssrf
  http.delete(api('/users/:id'), async ({ params }) => HttpResponse.json(params)),
];

// -------------------------------------------------------------------------
// An Express-style handler whose parameter is named `request`. Calling it is
// nonsense, but a name-only sink used to match anything spelled `request(`.
// -------------------------------------------------------------------------

type Handler = (request: (u: string) => void, res: unknown) => void;

export const makeHandler: Handler = (request, _res) => {
  const target = process.env.TARGET ?? '/health';
  // ok: cortex-javascript-ssrf
  request(target);
};

// -------------------------------------------------------------------------
// A local object that merely borrows the name `http`.
// -------------------------------------------------------------------------

const httpSimulator = {
  get: (route: string, handler: () => void) => ({ route, handler }),
};

export function declareRoute(route: string) {
  // ok: cortex-javascript-ssrf
  return httpSimulator.get(route, () => undefined);
}

// -------------------------------------------------------------------------
// A genuine axios call in the same file must still fire — the guard above
// must not be achieved by disabling the rule for TypeScript or for files
// that import msw.
// -------------------------------------------------------------------------

export async function proxy(userUrl: string) {
  // ruleid: cortex-javascript-ssrf
  const res = await axios.get(userUrl);
  return res.data;
}
