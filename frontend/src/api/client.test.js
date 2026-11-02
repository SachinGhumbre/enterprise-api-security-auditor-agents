import { getApiKey, setApiKey, setOnUnauthorized } from './client';

describe('api client auth', () => {
  beforeEach(() => {
    sessionStorage.clear();
    setApiKey('');
    setOnUnauthorized(null);
    global.fetch = jest.fn();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('request sends stored key and parses payload', async () => {
    setApiKey('op-123');
    global.fetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => '{"ok":true}',
    });
    const { knowledge } = require('./client');
    const body = await knowledge.stats();
    expect(body).toEqual({ ok: true });
    const [, options] = global.fetch.mock.calls[0];
    expect(options.headers['X-API-Key']).toBe('op-123');
  });

  test('no key header when signed out', async () => {
    global.fetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => '{}',
    });
    const { knowledge } = require('./client');
    await knowledge.stats();
    const [, options] = global.fetch.mock.calls[0];
    expect(options.headers['X-API-Key']).toBeUndefined();
  });

  test('401 fires the unauthorized hook then throws', async () => {
    setApiKey('stale-key');
    global.fetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
      text: async () => '{"error":"nope"}',
    });
    const seen = [];
    setOnUnauthorized((err) => seen.push(err.status));
    const { knowledge } = require('./client');
    await expect(knowledge.stats()).rejects.toMatchObject({ status: 401 });
    expect(seen).toEqual([401]);
  });

  test('key round-trips through sessionStorage', () => {
    expect(getApiKey()).toBe('');
    setApiKey('abc');
    expect(getApiKey()).toBe('abc');
    expect(sessionStorage.getItem('easa.api_key')).toBe('abc');
    setApiKey('');
    expect(getApiKey()).toBe('');
    expect(sessionStorage.getItem('easa.api_key')).toBeNull();
  });
});
