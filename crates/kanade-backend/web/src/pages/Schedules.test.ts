import { describe, expect, test } from 'bun:test';

import { summariseWhen, type WhenSpec } from './Schedules';

// The Schedules page crashed with "Cannot read properties of undefined
// (reading 'days')" whenever the list included a `when: { on: [...] }`
// event-trigger schedule (e.g. dakoku-toast-in/-out): `summariseWhen`
// only recognised `per_pc` / `per_target` / `calendar` and fell through
// to `when.calendar.days` for anything else, so a single event-trigger
// schedule anywhere in the fleet took down the whole page. Mirrors the
// backend's `impl Display for When` one-liners exactly so logs, audit
// payloads and the SPA read identically.
describe('summariseWhen', () => {
  test('per_pc once', () => {
    expect(summariseWhen({ per_pc: 'once' })).toBe('per_pc once');
  });

  test('per_pc once_per_version', () => {
    expect(summariseWhen({ per_pc: 'once_per_version' })).toBe('per_pc once_per_version');
  });

  test('per_target every <humantime>', () => {
    expect(summariseWhen({ per_target: { every: '6h' } })).toBe('per_target every 6h');
  });

  test('calendar with no days', () => {
    expect(summariseWhen({ calendar: { at: '09:00' } })).toBe('at 09:00');
  });

  test('calendar with days', () => {
    expect(summariseWhen({ calendar: { at: '09:00', days: ['mon-fri'] } })).toBe(
      'at 09:00 [mon-fri]',
    );
  });

  // The reproduction: an `on` trigger must not fall through to the
  // calendar branch.
  test('on-trigger schedule renders instead of crashing', () => {
    const when: WhenSpec = { on: ['logon', 'unlock'] };
    expect(summariseWhen(when)).toBe('on [logon,unlock]');
  });

  test('single on-trigger schedule', () => {
    expect(summariseWhen({ on: ['startup'] })).toBe('on [startup]');
  });
});
