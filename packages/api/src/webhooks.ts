import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { lookup as dnsLookup, type LookupAddress, type LookupOptions } from 'node:dns';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP, type LookupFunction } from 'node:net';
import type { EventStore, LensEvent, Logger } from '@soroban-lens/store';
import { ApiError } from './errors.js';
import { assertContractId, parseEventQuery } from './params.js';

/*
 * Webhook subscriptions: a client registers a URL plus an event filter, and the
 * server POSTs matching events to it.
 *
 * Two things shape the design.
 *
 * 1. This feature makes the server send HTTP requests to addresses chosen by
 *    anonymous clients, so it is an SSRF and a flooding risk by construction.
 *    It is disabled by default, and when enabled it is bounded at every layer:
 *    targets must be public http(s) hosts (checked at registration *and* on the
 *    connection actually made, which defeats DNS rebinding), redirects are never
 *    followed, deliveries to one subscription and to one host are rate limited
 *    no matter how many events or retries are pending, and the number of
 *    subscriptions overall and per host is capped.
 *
 * 2. The store is written by a separate indexer process, so the API cannot be
 *    told about new events. Each subscription keeps its own cursor and the
 *    dispatcher polls `EventStore.queryEvents` (ascending, keyset) with the
 *    subscription's filter — which reuses the exact filter semantics of the REST
 *    routes. A cursor only advances once an event is delivered or dead-lettered,
 *    so nothing is skipped.
 *
 * Subscriptions and dead letters live in memory: they do not survive a restart,
 * and clients re-register. That keeps this module out of the store's schema
 * (Module 2); a persistent registry is a follow-up.
 */

// ── Options ──────────────────────────────────────────────────────────────────

export interface WebhookOptions {
  /** The /webhooks routes answer 404 unless this is true. Disabled by default. */
  enabled?: boolean;
  /**
   * When set, every /webhooks route requires `Authorization: Bearer <token>`.
   * Recommended whenever the API is reachable by anyone you do not trust.
   */
  authToken?: string;
  /**
   * Allow loopback / private / link-local targets. Off by default, because it
   * lets a client aim the server at internal services; for local development
   * and tests only.
   */
  allowPrivateNetworks?: boolean;
  /** Most subscriptions held at once. Default 100. */
  maxSubscriptions?: number;
  /** Most subscriptions that may target one hostname. Default 5. */
  maxSubscriptionsPerHost?: number;
  /** Delivery attempts (retries included) per minute, per subscription. Default 60. */
  maxDeliveriesPerMinute?: number;
  /** Delivery attempts per minute to one hostname across all subscriptions. Default 120. */
  maxDeliveriesPerMinutePerHost?: number;
  /** Attempts per event before it is dead-lettered. Default 5. */
  maxAttempts?: number;
  /** First retry delay; doubles each attempt, capped at five minutes. Default 1000. */
  retryBaseMs?: number;
  /** Per-request timeout. Default 5000. */
  requestTimeoutMs?: number;
  /** How often subscriptions are checked for new events. Default 2000. */
  pollIntervalMs?: number;
  /** Events fetched per subscription per query. Default 50. */
  batchSize?: number;
  /** Dead letters kept per subscription (oldest dropped). Default 100. */
  deadLetterLimit?: number;
}

const DEFAULTS = {
  maxSubscriptions: 100,
  maxSubscriptionsPerHost: 5,
  maxDeliveriesPerMinute: 60,
  maxDeliveriesPerMinutePerHost: 120,
  maxAttempts: 5,
  retryBaseMs: 1000,
  requestTimeoutMs: 5000,
  pollIntervalMs: 2000,
  batchSize: 50,
  deadLetterLimit: 100,
} as const;

const MAX_RETRY_DELAY_MS = 5 * 60_000;
const MAX_URL_LENGTH = 2048;
const MIN_SECRET_LENGTH = 16;

// ── Public shapes ────────────────────────────────────────────────────────────

export interface WebhookFilter {
  contractId?: string;
  /** Topic prefix, as on the REST routes; `null` is a wildcard for that position. */
  topics?: (string | null)[];
  address?: string;
}

export interface DeadLetter {
  id: string;
  subscriptionId: string;
  eventId: string;
  attempts: number;
  lastError: string;
  failedAt: string;
}

export interface WebhookSubscription {
  id: string;
  url: string;
  filter: WebhookFilter;
  createdAt: string;
  delivered: number;
  deadLettered: number;
}

/** Returned once, at registration: the only time the signing secret is shown. */
export interface RegisteredWebhook extends WebhookSubscription {
  secret: string;
}

// ── Target validation (SSRF guard) ───────────────────────────────────────────

function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  const [a, b] = parts as [number, number, number, number];
  return (
    a === 0 || // "this" network
    a === 10 ||
    a === 127 || // loopback
    (a === 100 && b >= 64 && b <= 127) || // carrier-grade NAT
    (a === 169 && b === 254) || // link-local, incl. cloud metadata
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0 && parts[2] === 0) || // IETF protocol assignments
    (a === 198 && (b === 18 || b === 19)) || // benchmarking
    a >= 224 // multicast, reserved, broadcast
  );
}

/**
 * Whether an IP literal is somewhere a webhook must never be sent: loopback,
 * private, link-local, CGNAT, multicast, unspecified or reserved space, and
 * IPv4-mapped IPv6 forms of the same.
 */
export function isPrivateAddress(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) return isPrivateIPv4(ip);
  if (version !== 6) return true; // not an IP at all: refuse rather than guess

  const lower = ip.toLowerCase();
  const mappedDotted = /^(?:0{0,4}:){0,5}:?ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
  if (mappedDotted) return isPrivateIPv4(mappedDotted[1] as string);
  const mappedHex = /^(?:0{0,4}:){0,5}:?ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(lower);
  if (mappedHex) {
    const hi = parseInt(mappedHex[1] as string, 16);
    const lo = parseInt(mappedHex[2] as string, 16);
    return isPrivateIPv4(`${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`);
  }

  if (lower === '::' || lower === '::1') return true;
  const first = lower.startsWith('::') ? 0 : parseInt(lower.split(':')[0] as string, 16);
  return (
    (first & 0xfe00) === 0xfc00 || // unique local fc00::/7
    (first & 0xffc0) === 0xfe80 || // link-local fe80::/10
    (first & 0xff00) === 0xff00 // multicast
  );
}

const LOCAL_SUFFIXES = ['.localhost', '.local', '.internal', '.localdomain', '.home.arpa'];

function bareHostname(url: URL): string {
  // URL keeps the brackets on IPv6 literals.
  return url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
}

/**
 * Parse and vet a webhook target. Synchronous checks only (scheme, credentials,
 * literal IPs, obviously-local names); DNS is checked separately, both at
 * registration and again on every connection.
 */
export function parseWebhookUrl(raw: unknown, allowPrivate: boolean): URL {
  if (typeof raw !== 'string' || raw.trim() === '') {
    throw ApiError.badRequest('"url" is required.', 'url');
  }
  if (raw.length > MAX_URL_LENGTH) {
    throw ApiError.badRequest(`"url" must be at most ${MAX_URL_LENGTH} characters.`, 'url');
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw ApiError.badRequest('"url" is not a valid URL.', 'url');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw ApiError.badRequest('"url" must use http or https.', 'url');
  }
  if (url.username !== '' || url.password !== '') {
    throw ApiError.badRequest('"url" must not contain credentials.', 'url');
  }
  if (!allowPrivate) {
    const host = bareHostname(url);
    if (host === 'localhost' || LOCAL_SUFFIXES.some((suffix) => host.endsWith(suffix))) {
      throw ApiError.badRequest('"url" must not point at a local or internal host.', 'url');
    }
    if (isIP(host) !== 0 && isPrivateAddress(host)) {
      throw ApiError.badRequest('"url" must not point at a private or reserved address.', 'url');
    }
  }
  return url;
}

function resolveAll(hostname: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    dnsLookup(hostname, { all: true }, (err, addresses) => {
      if (err) reject(err);
      else resolve((addresses as LookupAddress[]).map((a) => a.address));
    });
  });
}

/** Registration-time DNS check: every address the name resolves to must be public. */
async function assertResolvesPublicly(url: URL): Promise<void> {
  const host = bareHostname(url);
  if (isIP(host) !== 0) return; // literal, already vetted
  let addresses: string[];
  try {
    addresses = await resolveAll(host);
  } catch {
    throw ApiError.badRequest(`"url" host "${host}" could not be resolved.`, 'url');
  }
  if (addresses.length === 0 || addresses.some(isPrivateAddress)) {
    throw ApiError.badRequest('"url" must not resolve to a private or reserved address.', 'url');
  }
}

/**
 * The lookup used for the real connection. Re-checking here (rather than
 * trusting the registration-time check) is what defeats DNS rebinding: the name
 * is resolved once, validated, and *that* answer is the one connected to.
 */
function guardedLookup(allowPrivate: boolean): LookupFunction {
  return (hostname, options, callback) => {
    dnsLookup(hostname, options as LookupOptions, (err, address, family) => {
      if (err) {
        callback(err, '', 0);
        return;
      }
      const list = Array.isArray(address) ? address.map((a) => a.address) : [address];
      if (!allowPrivate && list.some(isPrivateAddress)) {
        callback(
          Object.assign(new Error('target resolves to a private address'), { code: 'EBLOCKED' }),
          '',
          0,
        );
        return;
      }
      callback(null, address, family);
    });
  };
}

// ── Rate limiting ────────────────────────────────────────────────────────────

/**
 * Token bucket. The burst is a tenth of a minute's allowance so that a backlog
 * is metered out evenly instead of being sent in one volley.
 */
class RateLimiter {
  private tokens: number;
  private last = Date.now();
  private readonly capacity: number;

  constructor(private readonly perMinute: number) {
    this.capacity = Math.max(1, Math.ceil(perMinute / 10));
    this.tokens = this.capacity;
  }

  private refill(): void {
    const now = Date.now();
    this.tokens = Math.min(this.capacity, this.tokens + ((now - this.last) * this.perMinute) / 60_000);
    this.last = now;
  }

  /** Milliseconds until a token is available; 0 when one is. Does not consume. */
  waitMs(): number {
    this.refill();
    if (this.tokens >= 1) return 0;
    return Math.ceil(((1 - this.tokens) * 60_000) / this.perMinute);
  }

  consume(): void {
    this.refill();
    this.tokens -= 1;
  }
}

// ── Delivery ─────────────────────────────────────────────────────────────────

function sign(secret: string, timestamp: number, body: string): string {
  return createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
}

/**
 * Verify a delivery on the receiving side. Exported so receivers (and tests) use
 * the same definition: `X-Lens-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256
 * of "<t>.<raw body>">`. Rejects timestamps older than `toleranceSeconds` to
 * limit replay.
 */
export function verifyWebhookSignature(
  secret: string,
  header: string,
  body: string,
  toleranceSeconds = 300,
  nowSeconds = Math.floor(Date.now() / 1000),
): boolean {
  const parts = Object.fromEntries(
    header.split(',').map((kv) => {
      const i = kv.indexOf('=');
      return [kv.slice(0, i).trim(), kv.slice(i + 1).trim()];
    }),
  ) as Record<string, string | undefined>;
  const t = Number(parts['t']);
  const v1 = parts['v1'];
  if (!Number.isInteger(t) || !v1 || Math.abs(nowSeconds - t) > toleranceSeconds) return false;
  const expected = Buffer.from(sign(secret, t, body), 'hex');
  const given = Buffer.from(v1, 'hex');
  return expected.length === given.length && timingSafeEqual(expected, given);
}

function postJson(
  url: URL,
  body: string,
  headers: Record<string, string>,
  timeoutMs: number,
  allowPrivate: boolean,
): Promise<number> {
  return new Promise((resolve, reject) => {
    const send = (url.protocol === 'https:' ? httpsRequest : httpRequest) as typeof httpRequest;
    const req = send(
      url,
      {
        method: 'POST',
        headers: {
          ...headers,
          'Content-Type': 'application/json',
          'Content-Length': String(Buffer.byteLength(body)),
          'User-Agent': 'soroban-lens-webhooks',
        },
        lookup: guardedLookup(allowPrivate),
        timeout: timeoutMs,
        // One connection per delivery: no keep-alive pool to reuse across hosts.
        agent: false,
      },
      (res) => {
        // The body is irrelevant; draining it frees the socket. Redirects are
        // not followed by node:http, so a 3xx is simply a failed delivery.
        res.resume();
        res.on('end', () => resolve(res.statusCode ?? 0));
        res.on('error', reject);
      },
    );
    req.on('timeout', () => req.destroy(new Error(`timed out after ${timeoutMs}ms`)));
    req.on('error', reject);
    req.end(body);
  });
}

/** 5xx, 408 and 429 are worth retrying; any other 4xx will not change on a retry. */
function retryable(status: number): boolean {
  return status >= 500 || status === 408 || status === 429;
}

// ── Manager ──────────────────────────────────────────────────────────────────

interface Subscription {
  id: string;
  url: URL;
  filter: WebhookFilter;
  secret: string;
  createdAt: string;
  cursor: string | undefined;
  busy: boolean;
  removed: boolean;
  limiter: RateLimiter;
  delivered: number;
  deadLettered: number;
  deadLetters: DeadLetter[];
}

const FILTER_KEYS = new Set(['contractId', 'topics', 'address']);

export class WebhookManager {
  private readonly subs = new Map<string, Subscription>();
  private readonly hostLimiters = new Map<string, RateLimiter>();
  private readonly sleepers = new Set<() => void>();
  private timer: NodeJS.Timeout | undefined;
  private stopped = false;
  private readonly o: Required<Omit<WebhookOptions, 'authToken' | 'enabled'>>;
  private readonly authToken: string | undefined;

  constructor(
    private readonly store: EventStore,
    options: WebhookOptions,
    private readonly log: Logger,
  ) {
    this.o = {
      allowPrivateNetworks: options.allowPrivateNetworks ?? false,
      maxSubscriptions: options.maxSubscriptions ?? DEFAULTS.maxSubscriptions,
      maxSubscriptionsPerHost: options.maxSubscriptionsPerHost ?? DEFAULTS.maxSubscriptionsPerHost,
      maxDeliveriesPerMinute: options.maxDeliveriesPerMinute ?? DEFAULTS.maxDeliveriesPerMinute,
      maxDeliveriesPerMinutePerHost:
        options.maxDeliveriesPerMinutePerHost ?? DEFAULTS.maxDeliveriesPerMinutePerHost,
      maxAttempts: options.maxAttempts ?? DEFAULTS.maxAttempts,
      retryBaseMs: options.retryBaseMs ?? DEFAULTS.retryBaseMs,
      requestTimeoutMs: options.requestTimeoutMs ?? DEFAULTS.requestTimeoutMs,
      pollIntervalMs: options.pollIntervalMs ?? DEFAULTS.pollIntervalMs,
      batchSize: options.batchSize ?? DEFAULTS.batchSize,
      deadLetterLimit: options.deadLetterLimit ?? DEFAULTS.deadLetterLimit,
    };
    this.authToken = options.authToken;
  }

  // ── lifecycle ──────────────────────────────────────────────────────────────

  start(): void {
    if (this.timer || this.stopped) return;
    this.timer = setInterval(() => {
      for (const sub of this.subs.values()) void this.pump(sub);
    }, this.o.pollIntervalMs);
    // The dispatcher must never be the thing that keeps the process alive.
    this.timer.unref();
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    for (const wake of [...this.sleepers]) wake();
  }

  // ── management API ─────────────────────────────────────────────────────────

  /** Throws 401 unless the request carries the configured bearer token. */
  authorize(header: string | undefined): void {
    if (this.authToken === undefined) return;
    const match = /^Bearer\s+(.+)$/i.exec(header ?? '');
    const given = Buffer.from(match?.[1]?.trim() ?? '');
    const expected = Buffer.from(this.authToken);
    if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
      throw new ApiError(401, 'unauthorized', 'A valid bearer token is required for /webhooks.');
    }
  }

  async register(input: unknown): Promise<RegisteredWebhook> {
    if (typeof input !== 'object' || input === null || Array.isArray(input)) {
      throw ApiError.badRequest('The request body must be a JSON object.');
    }
    const body = input as Record<string, unknown>;

    const url = parseWebhookUrl(body['url'], this.o.allowPrivateNetworks);
    if (!this.o.allowPrivateNetworks) await assertResolvesPublicly(url);

    const filter = this.parseFilter(body['filter']);

    let secret: string;
    if (body['secret'] === undefined) {
      secret = randomBytes(32).toString('hex');
    } else if (typeof body['secret'] === 'string' && body['secret'].length >= MIN_SECRET_LENGTH) {
      secret = body['secret'];
    } else {
      throw ApiError.badRequest(`"secret" must be a string of at least ${MIN_SECRET_LENGTH} characters.`, 'secret');
    }

    if (this.subs.size >= this.o.maxSubscriptions) {
      throw new ApiError(429, 'too_many_webhooks', `At most ${this.o.maxSubscriptions} webhooks can be registered.`);
    }
    const host = bareHostname(url);
    const onHost = [...this.subs.values()].filter((s) => bareHostname(s.url) === host).length;
    if (onHost >= this.o.maxSubscriptionsPerHost) {
      throw new ApiError(
        429,
        'too_many_webhooks',
        `At most ${this.o.maxSubscriptionsPerHost} webhooks can target one host.`,
      );
    }

    // Start from "now": a new subscription sees events indexed after it
    // registered, not the whole history.
    const latest = await this.store.queryEvents({ ...filter, order: 'desc', limit: 1 });

    const sub: Subscription = {
      id: randomUUID(),
      url,
      filter,
      secret,
      createdAt: new Date().toISOString(),
      cursor: latest.events[0]?.id,
      busy: false,
      removed: false,
      limiter: new RateLimiter(this.o.maxDeliveriesPerMinute),
      delivered: 0,
      deadLettered: 0,
      deadLetters: [],
    };
    this.subs.set(sub.id, sub);
    this.log.info('webhook_registered', `webhook ${sub.id} registered for ${host}`, { id: sub.id, host });
    return { ...this.view(sub), secret };
  }

  list(): WebhookSubscription[] {
    return [...this.subs.values()].map((s) => this.view(s));
  }

  get(id: string): WebhookSubscription {
    return this.view(this.find(id));
  }

  remove(id: string): void {
    const sub = this.find(id);
    sub.removed = true;
    this.subs.delete(id);
    this.log.info('webhook_removed', `webhook ${id} removed`, { id });
  }

  deadLetters(id: string): DeadLetter[] {
    return [...this.find(id).deadLetters];
  }

  /** Run one dispatch pass for every subscription. Exposed so tests need not wait on the timer. */
  async pollOnce(): Promise<void> {
    await Promise.all([...this.subs.values()].map((sub) => this.pump(sub)));
  }

  // ── internals ──────────────────────────────────────────────────────────────

  private find(id: string): Subscription {
    const sub = this.subs.get(id);
    if (!sub) throw ApiError.notFound(`No webhook with id "${id}".`);
    return sub;
  }

  private view(sub: Subscription): WebhookSubscription {
    return {
      id: sub.id,
      url: sub.url.toString(),
      filter: sub.filter,
      createdAt: sub.createdAt,
      delivered: sub.delivered,
      deadLettered: sub.deadLettered,
    };
  }

  /** Validate the filter by running it through the REST parser, so both agree. */
  private parseFilter(raw: unknown): WebhookFilter {
    if (raw === undefined) return {};
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      throw ApiError.badRequest('"filter" must be an object.', 'filter');
    }
    const input = raw as Record<string, unknown>;
    for (const key of Object.keys(input)) {
      if (!FILTER_KEYS.has(key)) {
        throw ApiError.badRequest(
          `Unknown filter field "${key}". Supported: contractId, topics, address.`,
          'filter',
        );
      }
    }
    const params = new URLSearchParams();
    if (input['contractId'] !== undefined) {
      if (typeof input['contractId'] !== 'string') throw ApiError.badRequest('"filter.contractId" must be a string.', 'filter');
      params.set('contractId', input['contractId']);
    }
    if (input['address'] !== undefined) {
      if (typeof input['address'] !== 'string') throw ApiError.badRequest('"filter.address" must be a string.', 'filter');
      params.set('address', input['address']);
    }
    if (input['topics'] !== undefined) {
      const topics = input['topics'];
      if (!Array.isArray(topics) || topics.some((t) => t !== null && typeof t !== 'string')) {
        throw ApiError.badRequest('"filter.topics" must be an array of strings (null for a wildcard).', 'filter');
      }
      for (const topic of topics as (string | null)[]) params.append('topic', topic ?? '*');
    }
    const query = parseEventQuery(params);
    const contractId =
      typeof input['contractId'] === 'string' ? assertContractId(input['contractId']) : undefined;
    return {
      ...(contractId !== undefined ? { contractId } : {}),
      ...(query.topics ? { topics: query.topics } : {}),
      ...(query.address ? { address: query.address } : {}),
    };
  }

  private hostLimiter(host: string): RateLimiter {
    let limiter = this.hostLimiters.get(host);
    if (!limiter) {
      limiter = new RateLimiter(this.o.maxDeliveriesPerMinutePerHost);
      this.hostLimiters.set(host, limiter);
    }
    return limiter;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      const done = (): void => {
        clearTimeout(timer);
        this.sleepers.delete(done);
        resolve();
      };
      const timer = setTimeout(done, ms);
      timer.unref();
      this.sleepers.add(done);
    });
  }

  /**
   * Wait until both the subscription's and the host's budgets allow one more
   * attempt, then spend from both. Every attempt — a retry included — passes
   * through here, which is what makes the rate a hard ceiling.
   */
  private async throttle(sub: Subscription): Promise<void> {
    const host = this.hostLimiter(bareHostname(sub.url));
    for (;;) {
      if (this.stopped || sub.removed) return;
      const wait = Math.max(sub.limiter.waitMs(), host.waitMs());
      if (wait === 0) {
        sub.limiter.consume();
        host.consume();
        return;
      }
      await this.sleep(wait);
    }
  }

  private async pump(sub: Subscription): Promise<void> {
    if (sub.busy || sub.removed || this.stopped) return;
    sub.busy = true;
    try {
      for (;;) {
        const page = await this.store.queryEvents({
          ...sub.filter,
          order: 'asc',
          limit: this.o.batchSize,
          ...(sub.cursor ? { cursor: sub.cursor } : {}),
        });
        for (const event of page.events) {
          if (this.stopped || sub.removed) return;
          await this.deliver(sub, event);
          // Only after delivery or dead-lettering: a crash mid-delivery replays
          // the event rather than losing it.
          sub.cursor = event.id;
        }
        if (!page.nextCursor || page.events.length === 0) break;
      }
    } catch (error) {
      this.log.error('webhook_dispatch_failed', `dispatch for ${sub.id} failed: ${error instanceof Error ? error.message : String(error)}`, { id: sub.id });
    } finally {
      sub.busy = false;
    }
  }

  private async deliver(sub: Subscription, event: LensEvent): Promise<void> {
    // One id for every attempt, so a receiver can de-duplicate retries.
    const deliveryId = randomUUID();
    const body = JSON.stringify({ deliveryId, subscriptionId: sub.id, event });
    let lastError = 'unknown error';
    let attempts = 0;

    for (let attempt = 1; attempt <= this.o.maxAttempts; attempt++) {
      await this.throttle(sub);
      if (this.stopped || sub.removed) return;
      attempts = attempt;

      const timestamp = Math.floor(Date.now() / 1000);
      try {
        const status = await postJson(
          sub.url,
          body,
          {
            'X-Lens-Signature': `t=${timestamp},v1=${sign(sub.secret, timestamp, body)}`,
            'X-Lens-Delivery': deliveryId,
            'X-Lens-Event-Id': event.id,
            'X-Lens-Attempt': String(attempt),
          },
          this.o.requestTimeoutMs,
          this.o.allowPrivateNetworks,
        );
        if (status >= 200 && status < 300) {
          sub.delivered += 1;
          return;
        }
        lastError = `HTTP ${status}`;
        if (!retryable(status)) break;
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error);
      }

      if (attempt < this.o.maxAttempts) {
        await this.sleep(Math.min(this.o.retryBaseMs * 2 ** (attempt - 1), MAX_RETRY_DELAY_MS));
        if (this.stopped || sub.removed) return;
      }
    }

    sub.deadLettered += 1;
    sub.deadLetters.push({
      id: randomUUID(),
      subscriptionId: sub.id,
      eventId: event.id,
      attempts,
      lastError,
      failedAt: new Date().toISOString(),
    });
    while (sub.deadLetters.length > this.o.deadLetterLimit) sub.deadLetters.shift();
    this.log.warn(
      'webhook_dead_letter',
      `event ${event.id} for webhook ${sub.id} dead-lettered after ${attempts} attempt(s): ${lastError}`,
      { id: sub.id, eventId: event.id, attempts },
    );
  }
}
