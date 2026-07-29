import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { createHash } from 'node:crypto';
import { ApiClient, ApiResponse } from '../utils/api-client.js';

// ---------------------------------------------------------------------------
// Capture GovCon — HigherGov tools (rewritten to match HigherGov's live API)
//
// HigherGov public API base: https://www.highergov.com/api-external
// Auth: api_key as a query param (handled by ApiClient.highergovGet).
// Endpoints used: /contract/, /opportunity/, /people/
//
// Verified against live records 2026-07-29 (VA NAICS 485991 contracts and a
// live SAM opportunity). Field mappings below reflect the ACTUAL response
// schema, not the previous (hollow) guesses.
// ---------------------------------------------------------------------------

// ---- Cache (in-process LRU + TTL) for the three get_* lookups ----
const CACHE_TTL_MS = 15 * 60 * 1000;
const CACHE_MAX_ENTRIES = 500;
type CacheEntry = { value: any; expiresAt: number };
const cache = new Map<string, CacheEntry>();

function cloneCacheValue<T>(value: T): T {
  if (value === null || value === undefined) return value;
  return JSON.parse(JSON.stringify(value)) as T;
}
function apiKeyScope(apiKey: string): string {
  return createHash('sha256').update(apiKey).digest('hex').slice(0, 16);
}
function buildCacheKey(kind: string, id: string, apiKey: string): string {
  return `${kind}:${apiKeyScope(apiKey)}:${id}`;
}
function cacheGet(key: string): any | undefined {
  const hit = cache.get(key);
  if (!hit) return undefined;
  if (Date.now() > hit.expiresAt) { cache.delete(key); return undefined; }
  cache.delete(key); cache.set(key, hit);
  return cloneCacheValue(hit.value);
}
function cacheSet(key: string, value: any): void {
  if (cache.size >= CACHE_MAX_ENTRIES) {
    const oldest = cache.keys().next().value;
    if (oldest) cache.delete(oldest);
  }
  cache.set(key, { value: cloneCacheValue(value), expiresAt: Date.now() + CACHE_TTL_MS });
}

// ---- Standard error shape ----
type ErrorCode = 'not_found' | 'bad_request' | 'upstream_error' | 'rate_limited' | 'auth_failed';

class MissingHigherGovApiKeyError extends Error {
  constructor() {
    super('HigherGov API key required. Authorize the remote MCP connector or configure HIGHERGOV_API_KEY.');
    this.name = 'MissingHigherGovApiKeyError';
  }
}
function errorResponse(code: ErrorCode, message: string, retryAfterSeconds: number | null = null) {
  return { error: { code, message: String(message).slice(0, 300), retry_after_seconds: retryAfterSeconds } };
}
function upstreamStatus(err: string | undefined): number {
  const m = (err || '').match(/API Error (\d+)/);
  return m ? Number(m[1]) : 0;
}
function classifyUpstreamError(err: string | undefined): ReturnType<typeof errorResponse> {
  const text = err || 'Unknown upstream error';
  const status = upstreamStatus(err);
  if (status === 401 || status === 403) return errorResponse('auth_failed', 'Upstream authentication failed (check the HigherGov API key)');
  if (status === 404) return errorResponse('not_found', 'Resource not found');
  if (status === 400 || status === 422) return errorResponse('bad_request', text);
  if (status === 429) return errorResponse('rate_limited', 'Upstream rate limit hit', 60);
  return errorResponse('upstream_error', text);
}

function getApiKey(args: any): string {
  const key = args?.api_key || process.env.HIGHERGOV_API_KEY;
  if (!key) throw new MissingHigherGovApiKeyError();
  return key;
}

function extractId(idOrUrl: string): string {
  const trimmed = String(idOrUrl).trim();
  if (!trimmed.includes('://')) return trimmed;
  try {
    const u = new URL(trimmed);
    const segs = u.pathname.split('/').filter(Boolean);
    return segs[segs.length - 1] || trimmed;
  } catch { return trimmed; }
}

// ---- Agency name/abbreviation -> HigherGov agency_key (top-level federal) ----
const AGENCY_KEYS: Record<string, number> = {
  dhs: 100, 'homeland security': 100,
  dod: 101, defense: 101, 'department of defense': 101,
  va: 102, 'veterans affairs': 102, 'department of veterans affairs': 102,
  dos: 103, state: 103, 'department of state': 103,
  nasa: 104,
  gsa: 105, 'general services administration': 105,
  hhs: 106, 'health and human services': 106,
  usaid: 107,
  usda: 108, agriculture: 108, 'department of agriculture': 108,
  doj: 109, justice: 109, 'department of justice': 109,
};
// Returns an integer awarding_agency_key, or undefined if it can't be resolved.
// Accepts a raw integer/numeric string (used as-is — supports sub-agency keys
// like VISN 22 = 2033) or a known top-level name/abbreviation.
function resolveAgencyKey(agency: unknown): number | undefined {
  if (agency === undefined || agency === null || agency === '') return undefined;
  if (typeof agency === 'number' && Number.isFinite(agency)) return agency;
  const s = String(agency).trim();
  if (/^\d+$/.test(s)) return Number(s);
  const key = s.toLowerCase();
  if (AGENCY_KEYS[key] !== undefined) return AGENCY_KEYS[key];
  for (const [name, k] of Object.entries(AGENCY_KEYS)) {
    if (key.includes(name)) return k;
  }
  return undefined;
}

// ---- Local value helpers (self-contained; no external slug dependency) ----
function str(v: unknown): string { return v === null || v === undefined ? '' : String(v); }
function strOrNull(v: unknown): string | null { return v === null || v === undefined || v === '' ? null : String(v); }
function intOrNull(v: unknown): number | null {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? Math.round(n) : null;
}
function iso(v: unknown): string | null {
  const s = strOrNull(v);
  return s ? s.slice(0, 10) : null; // HigherGov already returns YYYY-MM-DD
}
function trunc(v: unknown, n: number): string | null {
  const s = strOrNull(v);
  if (!s) return null;
  return s.length > n ? s.slice(0, n) + '…' : s;
}
function firstCode(v: unknown): string | undefined {
  if (Array.isArray(v)) return v.length ? String(v[0]) : undefined;
  const s = strOrNull(v);
  return s ?? undefined;
}
function agencyName(a: any): string | null {
  if (!a) return null;
  if (typeof a === 'string') return a;
  return a.agency_name ?? a.agency_abbreviation ?? null;
}

// ---- Response helpers ----
function resultArray(raw: any): any[] {
  const list = raw?.results ?? raw?.data?.results ?? raw?.data ?? [];
  return Array.isArray(list) ? list : [];
}
// HigherGov paginates via meta.pagination {page, pages}. Return the next page
// number as a string cursor, or null at the ceiling.
function nextPage(raw: any): string | null {
  const p = raw?.meta?.pagination ?? raw?.data?.meta?.pagination;
  if (!p) return null;
  const page = Number(p.page), pages = Number(p.pages);
  if (Number.isFinite(page) && Number.isFinite(pages) && page < pages) return String(page + 1);
  return null;
}
function pageArg(cursor: unknown): number | undefined {
  if (cursor === null || cursor === undefined || cursor === '') return undefined;
  const n = Number(cursor);
  return Number.isFinite(n) && n > 0 ? Math.round(n) : undefined;
}

// ---- Normalizers (mapped to HigherGov's real field names) ----
function normalizeContractSummary(raw: any) {
  return {
    award_id: str(raw.award_id),               // government PIID
    parent_award_id: strOrNull(raw.parent_award_id),
    award_type: strOrNull(raw.award_type),
    awardee_name: str(raw.awardee?.clean_name),
    awardee_uei: strOrNull(raw.awardee?.uei),
    awardee_cage: strOrNull(raw.awardee?.cage_code),
    awardee_key: intOrNull(raw.awardee?.awardee_key),
    parent_name: strOrNull(raw.awardee_parent?.clean_name),
    parent_uei: strOrNull(raw.awardee_parent?.uei),
    parent_key: intOrNull(raw.awardee_parent?.awardee_key),
    agency: agencyName(raw.awarding_agency),
    agency_key: intOrNull(raw.awarding_agency?.agency_key),
    funding_agency: agencyName(raw.funding_agency),
    naics: strOrNull(raw.naics_code?.naics_code),
    naics_description: strOrNull(raw.naics_code?.naics_description),
    psc: strOrNull(raw.psc_code?.psc_code),
    psc_description: strOrNull(raw.psc_code?.psc_description),
    set_aside: strOrNull(raw.type_of_set_aside),
    extent_competed: strOrNull(raw.extent_competed),
    number_of_offers_received: intOrNull(raw.number_of_offers_received),
    total_dollars_obligated: intOrNull(raw.total_dollars_obligated), // use THIS for $ (value fields can be 0)
    pop_start: iso(raw.period_of_performance_start_date),
    pop_end: iso(raw.period_of_performance_current_end_date),
    place_of_performance_state: strOrNull(raw.primary_place_of_performance_state_code),
    source_url: str(raw.path),                 // clean highergov.com URL (no key)
  };
}

function normalizeContractFull(raw: any) {
  return {
    ...normalizeContractSummary(raw),
    pop_potential_end: iso(raw.period_of_performance_potential_end_date),
    latest_action_date: iso(raw.latest_action_date),
    last_modified_date: iso(raw.last_modified_date),
    latest_transaction_key: strOrNull(raw.latest_transaction_key), // encodes the modification (…_P00001_…)
    solicitation_procedures: strOrNull(raw.solicitation_procedures),
    other_than_full_and_open_competition: strOrNull(raw.other_than_full_and_open_competition),
    fair_opportunity_limited_sources: strOrNull(raw.fair_opportunity_limited_sources),
    type_of_contract_pricing: strOrNull(raw.type_of_contract_pricing_description),
    current_total_value_of_award: intOrNull(raw.current_total_value_of_award),
    potential_total_value_of_award: intOrNull(raw.potential_total_value_of_award),
    place_of_performance: {
      city: strOrNull(raw.primary_place_of_performance_city_name),
      county: strOrNull(raw.primary_place_of_performance_county_name),
      state: strOrNull(raw.primary_place_of_performance_state_code),
      zip: strOrNull(raw.primary_place_of_performance_zip),
      country: strOrNull(raw.primary_place_of_performance_country_name),
    },
    contracting_officer: raw.approved_by ?? null,   // {name,email,phone,title} when present
    contract_specialist: raw.created_by ?? null,
    vehicle: strOrNull(raw.vehicle),
    document_path: strOrNull(raw.document_path),     // parse related_key for get_highergov documents
  };
}

function contactBlock(c: any) {
  if (!c) return null;
  return {
    name: strOrNull(c.contact_name) ?? [c.contact_first_name, c.contact_last_name].filter(Boolean).join(' ') || null,
    email: strOrNull(c.contact_email),
    phone: strOrNull(c.contact_phone),
    title: strOrNull(c.contact_title),
  };
}

function normalizeOpportunity(raw: any) {
  const oppType = typeof raw.opp_type === 'object' && raw.opp_type
    ? (raw.opp_type.description ?? raw.opp_type.name ?? null)
    : (raw.opp_type ?? null);
  return {
    opportunity_id: str(raw.opp_key ?? raw.version_key),
    sam_notice_id: strOrNull(raw.source_id),          // SAM.gov solicitation/notice number
    source_type: strOrNull(raw.source_type),
    category: strOrNull(raw.opp_cat),
    type: strOrNull(oppType),
    title: str(raw.title),
    agency: agencyName(raw.agency),
    agency_key: intOrNull(raw.agency?.agency_key),
    naics: strOrNull(raw.naics_code?.naics_code),
    psc: strOrNull(raw.psc_code?.psc_code),
    product_service: strOrNull(raw.product_service),
    set_aside: strOrNull(raw.set_aside),
    sole_source: raw.sole_source_flag === true ? true : (raw.sole_source_flag === false ? false : null),
    posted_date: iso(raw.posted_date),
    due_date: iso(raw.due_date),
    captured_date: iso(raw.captured_date),
    est_value_low: intOrNull(raw.val_est_low),
    est_value_high: intOrNull(raw.val_est_high),
    place_of_performance: {
      city: strOrNull(raw.pop_city), state: strOrNull(raw.pop_state),
      zip: strOrNull(raw.pop_zip), country: strOrNull(raw.pop_country),
    },
    primary_contact: contactBlock(raw.primary_contact_email),
    secondary_contact: contactBlock(raw.secondary_contact_email),
    summary: trunc(raw.ai_summary ?? raw.description_text, 2000),
    source_url: str(raw.path),                        // clean highergov.com URL
    sam_url: strOrNull(raw.source_path),              // sam.gov/opp/... page (primary source)
    document_path: strOrNull(raw.document_path),
  };
}

function normalizePersonSummary(raw: any) {
  return {
    name: strOrNull(raw.contact_name) ?? [raw.contact_first_name, raw.contact_last_name].filter(Boolean).join(' ') || null,
    email: strOrNull(raw.contact_email ?? raw.email),
    phone: strOrNull(raw.contact_phone ?? raw.phone),
    title: strOrNull(raw.contact_title ?? raw.title),
    agency: agencyName(raw.agency),
    last_seen: iso(raw.last_seen),
    source_url: str(raw.path ?? ''),
  };
}

// ---------------------------------------------------------------------------
export const highergovTools = {
  async getTools(): Promise<Tool[]> {
    return [
      {
        name: 'search_highergov_contracts',
        description:
          'Search awarded federal contracts (FPDS-derived) with rich competition and award detail: incumbent (awardee/parent UEI+CAGE), extent_competed, number_of_offers_received, set-aside, obligated dollars, period-of-performance dates. At least one of agency, naics, psc, award_id, awardee_key, or search_id is required. Use to find incumbents and recompete candidates.',
        inputSchema: {
          type: 'object',
          properties: {
            agency: { type: 'string', description: 'Awarding agency — name, abbreviation (e.g. "VA", "DoD"), or a HigherGov numeric agency_key (sub-agencies must be passed as their numeric key, e.g. VISN 22 = 2033).' },
            naics: { type: 'string', description: 'NAICS code (single). Arrays accepted; only the first is sent.' },
            psc: { type: 'string', description: 'PSC / Product Service Code (single).' },
            award_id: { type: 'string', description: 'Government PIID for a single contract.' },
            awardee_key: { type: 'number', description: 'HigherGov awardee_key (integer, NOT a UEI). Resolve from a prior contract record.' },
            search_id: { type: 'string', description: 'HigherGov saved-search ID.' },
            last_modified_date: { type: 'string', description: 'YYYY-MM-DD; only records modified on/after are returned (HigherGov has no PoP-date filter).' },
            pop_end_after: { type: 'string', description: 'YYYY-MM-DD; client-side filter on period_of_performance current end date.' },
            pop_end_before: { type: 'string', description: 'YYYY-MM-DD; client-side filter on period_of_performance current end date.' },
            min_value: { type: 'number', description: 'USD; client-side filter on total_dollars_obligated.' },
            max_value: { type: 'number', description: 'USD; client-side filter on total_dollars_obligated.' },
            limit: { type: 'number', description: 'Page size, default 50, max 100.' },
            cursor: { type: 'string', description: 'Page number from a prior next_cursor.' },
          },
          required: [],
        },
      },
      {
        name: 'get_highergov_contract',
        description:
          'Get the full record for one federal contract by government PIID (award_id). Returns incumbent, competition posture, obligated value, PoP dates, modification key, place of performance, and the contracting officer/specialist when present.',
        inputSchema: {
          type: 'object',
          properties: { id: { type: 'string', description: 'Government PIID / HigherGov award_id (or a HigherGov contract URL).' } },
          required: ['id'],
        },
      },
      {
        name: 'search_highergov_opportunities',
        description:
          'Search live/historical federal (SAM), SLED, grant, and SBIR opportunities. Requires at least one of: keyword, agency, naics, posted_date, captured_date, search_id, or source_id. Returns title, agency, NAICS/PSC, set-aside, posted/due dates, value estimates, contacts, and the SAM.gov source URL.',
        inputSchema: {
          type: 'object',
          properties: {
            keyword: { type: 'string', description: 'Free-text keyword.' },
            agency: { type: 'string', description: 'Agency name/abbreviation or numeric agency_key.' },
            naics: { type: 'string', description: 'NAICS code.' },
            posted_date: { type: 'string', description: 'YYYY-MM-DD posted-date filter.' },
            captured_date: { type: 'string', description: 'YYYY-MM-DD captured (snapshot) date.' },
            search_id: { type: 'string', description: 'HigherGov saved-search ID.' },
            source_id: { type: 'string', description: 'Source solicitation/notice number (e.g. SAM notice id).' },
            status: { type: 'string', description: '"open" or "closed".' },
            limit: { type: 'number', description: 'Page size, default 25, max 100.' },
            cursor: { type: 'string', description: 'Page number from a prior next_cursor.' },
          },
          required: [],
        },
      },
      {
        name: 'get_highergov_opportunity',
        description:
          'Get one opportunity by HigherGov opp_key, SAM notice id (source_id), or URL. Returns full agency, NAICS/PSC, set-aside, dates, value estimates, contacts, description, and the SAM.gov source link.',
        inputSchema: {
          type: 'object',
          properties: { id: { type: 'string', description: 'HigherGov opp_key, SAM notice id, or opportunity URL.' } },
          required: ['id'],
        },
      },
      {
        name: 'search_highergov_people',
        description:
          'Look up a federal/SLED point of contact by exact email, or browse most-recently-seen contacts. NOTE: HigherGov exposes no agency/role filter on people — you generally need the email already. For a named buyer on a specific award, read the CO/CS off get_highergov_contract instead.',
        inputSchema: {
          type: 'object',
          properties: {
            contact_email: { type: 'string', description: 'Exact contact email to look up.' },
            ordering: { type: 'string', description: 'e.g. "-last_seen".' },
            limit: { type: 'number', description: 'Page size, default 20, max 100.' },
            cursor: { type: 'string', description: 'Page number from a prior next_cursor.' },
          },
          required: [],
        },
      },
      {
        name: 'get_highergov_person',
        description: 'Get a federal/SLED POC profile by exact contact email.',
        inputSchema: {
          type: 'object',
          properties: { id: { type: 'string', description: 'Contact email address.' } },
          required: ['id'],
        },
      },
    ];
  },

  async callTool(name: string, args: any): Promise<any> {
    const sanitized = ApiClient.sanitizeInput(args);
    try {
      switch (name) {
        case 'search_highergov_contracts': return await this.searchContracts(sanitized);
        case 'get_highergov_contract': return await this.getContract(sanitized);
        // Back-compat alias: the old build exposed "search_highergov_forecasts".
        case 'search_highergov_forecasts':
        case 'search_highergov_opportunities': return await this.searchOpportunities(sanitized);
        case 'get_highergov_opportunity': return await this.getOpportunity(sanitized);
        case 'search_highergov_people': return await this.searchPeople(sanitized);
        case 'get_highergov_person': return await this.getPerson(sanitized);
        default: throw new Error(`Unknown HigherGov tool: ${name}`);
      }
    } catch (err) {
      if (err instanceof MissingHigherGovApiKeyError) return errorResponse('auth_failed', err.message);
      return errorResponse('bad_request', err instanceof Error ? err.message : String(err));
    }
  },

  async searchContracts(args: any) {
    const apiKey = getApiKey(args);

    const agencyKey = resolveAgencyKey(args.agency);
    const naics = firstCode(args.naics);
    const psc = firstCode(args.psc);
    const hasFilter = agencyKey !== undefined || naics || psc || args.award_id || args.awardee_key || args.search_id;
    if (!hasFilter) {
      return errorResponse('bad_request', 'Provide at least one of: agency, naics, psc, award_id, awardee_key, or search_id.');
    }
    if (args.agency && agencyKey === undefined) {
      return errorResponse('bad_request', `Could not resolve agency "${args.agency}" to a HigherGov agency_key. Pass a numeric agency_key (e.g. VA=102, VISN 22=2033).`);
    }

    const limit = Math.min(Math.max(Number(args.limit) || 50, 1), 100);
    const params: Record<string, any> = { page_size: limit };
    if (agencyKey !== undefined) params.awarding_agency_key = agencyKey;
    if (naics) params.naics_code = naics;
    if (psc) params.psc_code = psc;
    if (args.award_id) params.award_id = extractId(String(args.award_id));
    if (args.awardee_key !== undefined) params.awardee_key = Number(args.awardee_key);
    if (args.search_id) params.search_id = String(args.search_id);
    if (args.last_modified_date) params.last_modified_date = String(args.last_modified_date);
    const page = pageArg(args.cursor);
    if (page) params.page_number = page;

    const res: ApiResponse = await ApiClient.highergovGet('/contract/', params, apiKey);
    if (!res.success) return classifyUpstreamError(res.error);

    let results = resultArray(res.data).map(normalizeContractSummary);

    // Client-side filters HigherGov's /contract/ endpoint doesn't support natively.
    if (args.pop_end_after) results = results.filter(r => r.pop_end && r.pop_end >= String(args.pop_end_after).slice(0, 10));
    if (args.pop_end_before) results = results.filter(r => r.pop_end && r.pop_end <= String(args.pop_end_before).slice(0, 10));
    if (args.min_value !== undefined) results = results.filter(r => (r.total_dollars_obligated ?? 0) >= Number(args.min_value));
    if (args.max_value !== undefined) results = results.filter(r => (r.total_dollars_obligated ?? 0) <= Number(args.max_value));

    return { results, next_cursor: nextPage(res.data), total: res.data?.meta?.pagination?.count ?? null };
  },

  async getContract(args: any) {
    const apiKey = getApiKey(args);
    if (!args.id) return errorResponse('bad_request', 'id (award_id / PIID) is required');
    const id = extractId(String(args.id));
    const cacheKey = buildCacheKey('contract', id, apiKey);
    const cached = cacheGet(cacheKey);
    if (cached) return cached;

    const res = await ApiClient.highergovGet('/contract/', { award_id: id, page_size: 1 }, apiKey);
    if (!res.success) return classifyUpstreamError(res.error);
    const list = resultArray(res.data);
    if (!list.length) return errorResponse('not_found', `No contract found for award_id "${id}".`);
    const result = normalizeContractFull(list[0]);
    cacheSet(cacheKey, result);
    return result;
  },

  async searchOpportunities(args: any) {
    const apiKey = getApiKey(args);
    const agencyKey = resolveAgencyKey(args.agency);
    const naics = firstCode(args.naics); // client-side only — /opportunity/ has no naics filter
    const hasFilter = args.keyword || agencyKey !== undefined ||
      args.posted_date || args.captured_date || args.search_id || args.source_id;
    if (!hasFilter) {
      return errorResponse('bad_request', 'Provide at least one API filter: keyword, agency, posted_date, captured_date, search_id, or source_id. (naics is applied client-side and does not count on its own.)');
    }
    if (args.agency && agencyKey === undefined) {
      return errorResponse('bad_request', `Could not resolve agency "${args.agency}" to a HigherGov agency_key.`);
    }

    const limit = Math.min(Math.max(Number(args.limit) || 25, 1), 100);
    const params: Record<string, any> = { page_size: limit };
    if (args.keyword) params.keyword = String(args.keyword);
    if (agencyKey !== undefined) params.agency_key = agencyKey;
    if (args.posted_date) params.posted_date = String(args.posted_date);
    if (args.captured_date) params.captured_date = String(args.captured_date);
    if (args.search_id) params.search_id = String(args.search_id);
    if (args.source_id) params.source_id = String(args.source_id);
    if (args.status) params.status = String(args.status);
    const page = pageArg(args.cursor);
    if (page) params.page_number = page;

    const res = await ApiClient.highergovGet('/opportunity/', params, apiKey);
    if (!res.success) return classifyUpstreamError(res.error);
    let results = resultArray(res.data).map(normalizeOpportunity);
    if (naics) results = results.filter(r => r.naics === naics); // client-side NAICS filter
    return {
      results,
      next_cursor: nextPage(res.data),
      total: res.data?.meta?.pagination?.count ?? null,
    };
  },

  async getOpportunity(args: any) {
    const apiKey = getApiKey(args);
    if (!args.id) return errorResponse('bad_request', 'id is required');
    const id = extractId(String(args.id));
    const cacheKey = buildCacheKey('opportunity', id, apiKey);
    const cached = cacheGet(cacheKey);
    if (cached) return cached;

    const tried: string[] = [];
    for (const param of ['opp_key', 'source_id'] as const) {
      tried.push(param);
      const res = await ApiClient.highergovGet('/opportunity/', { [param]: id, page_size: 1 }, apiKey);
      if (!res.success) return classifyUpstreamError(res.error);
      const list = resultArray(res.data);
      if (list.length) {
        const result = normalizeOpportunity(list[0]);
        cacheSet(cacheKey, result);
        return result;
      }
    }
    return errorResponse('not_found', `No opportunity found for id "${id}". Tried: ${tried.join(', ')}.`);
  },

  async searchPeople(args: any) {
    const apiKey = getApiKey(args);
    const limit = Math.min(Math.max(Number(args.limit) || 20, 1), 100);
    const params: Record<string, any> = { page_size: limit };
    if (args.contact_email) params.contact_email = String(args.contact_email);
    if (args.ordering) params.ordering = String(args.ordering);
    const page = pageArg(args.cursor);
    if (page) params.page_number = page;

    const res = await ApiClient.highergovGet('/people/', params, apiKey);
    if (!res.success) return classifyUpstreamError(res.error);
    return { results: resultArray(res.data).map(normalizePersonSummary), next_cursor: nextPage(res.data) };
  },

  async getPerson(args: any) {
    const apiKey = getApiKey(args);
    if (!args.id) return errorResponse('bad_request', 'id (contact email) is required');
    const email = extractId(String(args.id));
    const cacheKey = buildCacheKey('person', email, apiKey);
    const cached = cacheGet(cacheKey);
    if (cached) return cached;

    const res = await ApiClient.highergovGet('/people/', { contact_email: email, page_size: 1 }, apiKey);
    if (!res.success) return classifyUpstreamError(res.error);
    const list = resultArray(res.data);
    if (!list.length) return errorResponse('not_found', `No person found for "${email}".`);
    const result = normalizePersonSummary(list[0]);
    cacheSet(cacheKey, result);
    return result;
  },
};
