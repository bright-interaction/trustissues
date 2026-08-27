import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  api,
  ApiError,
  PRIVATE_INGRESS_REQUIRED_CODE,
  PRIVATE_INGRESS_REQUIRED_MESSAGE,
  request,
  requestIngressHealth,
  setPrivateIngressRequiredHandler,
} from '@/lib/api';

afterEach(() => {
  setPrivateIngressRequiredHandler(undefined);
  vi.unstubAllGlobals();
});

describe('private-ingress API UX', () => {
  it('turns the stable refusal code into actionable guidance while preserving its body', async () => {
    const onPrivateRequired = vi.fn();
    setPrivateIngressRequiredHandler(onPrivateRequired);
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            error: 'private ingress required',
            code: PRIVATE_INGRESS_REQUIRED_CODE,
          }),
          { status: 403, headers: { 'Content-Type': 'application/json' } }
        )
      )
    );

    let thrown: unknown;
    try {
      await request('/vault/unlock', { method: 'POST', body: '{}' });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(ApiError);
    expect(thrown).toMatchObject({
      status: 403,
      message: PRIVATE_INGRESS_REQUIRED_MESSAGE,
      body: {
        error: 'private ingress required',
        code: PRIVATE_INGRESS_REQUIRED_CODE,
      },
    });
    expect(onPrivateRequired).toHaveBeenCalledOnce();
    expect(PRIVATE_INGRESS_REQUIRED_MESSAGE).toMatch(/private TrustIssues URL/i);
    expect(PRIVATE_INGRESS_REQUIRED_MESSAGE).toMatch(/exact address/i);
    expect(PRIVATE_INGRESS_REQUIRED_MESSAGE).toMatch(/Sign-in, MFA, and permissions still apply/i);

    const [path, options] = (fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(path).toBe('/api/vault/unlock');
    expect(options.credentials).toBe('same-origin');
  });

  it('verifies ingress on the same browser origin without accepting an unknown stamp', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          status: 'ok',
          version: 'test',
          ingress: 'private',
          base_url: 'https://vault-internal.example.test',
          private_ingress_enabled: true,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    );
    vi.stubGlobal('fetch', fetchMock);

    await expect(requestIngressHealth()).resolves.toMatchObject({ ingress: 'private' });
    expect(fetchMock).toHaveBeenCalledWith(
      '/health',
      expect.objectContaining({
        credentials: 'same-origin',
        cache: 'no-store',
        signal: expect.any(AbortSignal),
      })
    );

    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ ingress: 'header-claimed-private' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );
    await expect(requestIngressHealth()).rejects.toThrow(/invalid ingress stamp/i);
  });

  it('sends an explicitly selected collection policy to the backend', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          id: 'collection-1',
          name: 'Internal operations',
          description: '',
          private_access_policy: 'sensitive_private',
          role: 'manager',
          created_at: null,
          updated_at: null,
        }),
        { status: 201, headers: { 'Content-Type': 'application/json' } }
      )
    );
    vi.stubGlobal('fetch', fetchMock);

    await api.collections.create({
      name: 'Internal operations',
      description: '',
      private_access_policy: 'sensitive_private',
    });

    expect(fetchMock).toHaveBeenCalledOnce();
    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(String(options.body))).toEqual({
      name: 'Internal operations',
      description: '',
      private_access_policy: 'sensitive_private',
    });
  });
});
