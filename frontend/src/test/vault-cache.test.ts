import { describe, expect, it } from 'vitest';
import {
  mergeUnlockedCustomFields,
  mergeUnlockedProviderMeta,
  mergeUnlockedVaultEntry,
} from '@/lib/vault-cache';
import type { VaultEntry } from '@/lib/vault-types';

function entry(over: Partial<VaultEntry> = {}): VaultEntry {
  return {
    id: 'entry-1',
    name: 'Production token',
    url: '',
    alias_url: '',
    username: '',
    value: 'old-primary',
    category: 'api_key',
    notes: '',
    rotation_interval_days: null,
    expires_at: null,
    last_rotated_at: null,
    rotation_status: 'fresh',
    provider: 'backblaze',
    provider_meta: '{"account_id":"acct","application_key":"secondary-secret","region":"old"}',
    provider_meta_withheld: [],
    auto_rotate: false,
    last_rotation_error: '',
    collection_id: null,
    custom_fields: [
      { label: 'Recovery PIN', value: '739201', secret: true },
      { label: 'Region', value: 'eu-north-1', secret: false },
    ],
    created_at: '',
    updated_at: '',
    ...over,
  };
}

describe('unlocked provider metadata merge', () => {
  it('restores only keys the server explicitly marked withheld', () => {
    const merged = mergeUnlockedProviderMeta(
      '{"account_id":"acct","application_key":"secondary-secret","region":"old","removed":"old"}',
      '{"account_id":"acct","region":"new"}',
      ['application_key']
    );

    expect(JSON.parse(merged!)).toEqual({
      account_id: 'acct',
      application_key: 'secondary-secret',
      region: 'new',
    });
  });

  it('takes an unredacted response authoritatively and fails closed on malformed redaction', () => {
    expect(
      mergeUnlockedProviderMeta('{"secret":"old"}', '{"region":"new"}', [])
    ).toBe('{"region":"new"}');
    expect(
      mergeUnlockedProviderMeta('{"secret":"old"}', 'not-json', ['secret'])
    ).toBe('{"secret":"old"}');
  });
});

describe('unlocked custom-field merge', () => {
  it('restores a withheld secret only at the same position and keeps ordinary updates', () => {
    expect(
      mergeUnlockedCustomFields(
        [
          { label: 'Recovery PIN', value: '739201', secret: true },
          { label: 'Region', value: 'eu-north-1', secret: false },
        ],
        [
          { label: 'Recovery PIN', value: '', secret: true, withheld: true },
          { label: 'Region', value: 'eu-west-1', secret: false },
        ]
      )
    ).toEqual([
      { label: 'Recovery PIN', value: '739201', secret: true },
      { label: 'Region', value: 'eu-west-1', secret: false },
    ]);
  });

  it('never borrows across a position mismatch and accepts an explicit clear', () => {
    expect(
      mergeUnlockedCustomFields(
        [{ label: 'First secret', value: 'do-not-borrow', secret: true }],
        [{ label: 'Different secret', value: '', secret: true, withheld: true }]
      )
    ).toEqual([{ label: 'Different secret', value: '', secret: true, withheld: true }]);
    expect(
      mergeUnlockedCustomFields(
        [{ label: 'First secret', value: 'do-not-keep', secret: true }],
        []
      )
    ).toEqual([]);
  });
});

it('merges a rotation echo without blanking unlocked secondary credentials', () => {
  const revealed = entry();
  const merged = mergeUnlockedVaultEntry(revealed, {
    value: 'rotated-primary',
    rotation_status: 'fresh',
    pending_revoke: null,
    provider_meta: '{"account_id":"acct","region":"new"}',
    provider_meta_withheld: ['application_key'],
    custom_fields: [
      { label: 'Recovery PIN', value: '', secret: true, withheld: true },
      { label: 'Region', value: 'eu-west-1', secret: false },
    ],
  });

  expect(merged.value).toBe('rotated-primary');
  expect(merged.pending_revoke).toBeNull();
  expect(JSON.parse(merged.provider_meta!)).toEqual({
    account_id: 'acct',
    application_key: 'secondary-secret',
    region: 'new',
  });
  expect(merged.custom_fields).toEqual([
    { label: 'Recovery PIN', value: '739201', secret: true },
    { label: 'Region', value: 'eu-west-1', secret: false },
  ]);
});

it('never transplants a withheld credential across a provider change', () => {
  const revealed = entry({
    provider: 'legacy-provider',
    provider_meta: '{"app_key":"old-provider-secret","region":"old"}',
  });
  const merged = mergeUnlockedVaultEntry(revealed, {
    provider: 'datadog',
    provider_meta: '{"site":"datadoghq.eu"}',
    provider_meta_withheld: ['app_key'],
  });

  expect(merged.provider).toBe('datadog');
  expect(JSON.parse(merged.provider_meta!)).toEqual({ site: 'datadoghq.eu' });
  expect(merged.provider_meta).not.toContain('old-provider-secret');
});
