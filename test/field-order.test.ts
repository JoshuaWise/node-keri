import {
	CANONICAL_FIELD_ORDER,
	toCanonicalEvent,
} from '../src/event/field-order';
import { InvalidArgumentError } from '../src/profile/errors';

describe('toCanonicalEvent', () => {
	test('reorders inception fields into KERI canonical order', () => {
		const scrambled = {
			a: [],
			k: ['k0'],
			i: 'AID',
			t: 'icp',
			d: 'D',
			v: 'V',
			s: '0',
			n: ['n0'],
			b: [],
			kt: '1',
			c: [],
			nt: '1',
			bt: '0',
		};
		expect(Object.keys(toCanonicalEvent(scrambled))).toEqual(
			CANONICAL_FIELD_ORDER.icp
		);
	});

	test('reorders rotation fields into KERI canonical order', () => {
		const scrambled = {
			ba: [],
			t: 'rot',
			a: [],
			p: 'P',
			d: 'D',
			v: 'V',
			i: 'AID',
			n: ['n0'],
			s: '1',
			k: ['k0'],
			nt: '1',
			br: [],
			kt: '1',
			bt: '0',
		};
		expect(Object.keys(toCanonicalEvent(scrambled))).toEqual(
			CANONICAL_FIELD_ORDER.rot
		);
	});

	test('reorders interaction fields into KERI canonical order', () => {
		const scrambled = { a: [], p: 'P', s: '1', i: 'AID', d: 'D', t: 'ixn', v: 'V' };
		expect(Object.keys(toCanonicalEvent(scrambled))).toEqual(
			CANONICAL_FIELD_ORDER.ixn
		);
	});

	test('preserves field values, only their order changes', () => {
		const event = {
			t: 'ixn',
			a: [{ x: 1 }],
			p: 'PREV',
			s: '2',
			i: 'AID',
			d: 'DIGEST',
			v: 'VERSION',
		};
		expect(toCanonicalEvent(event)).toEqual({
			v: 'VERSION',
			t: 'ixn',
			d: 'DIGEST',
			i: 'AID',
			s: '2',
			p: 'PREV',
			a: [{ x: 1 }],
		});
	});

	test('skips absent fields rather than emitting undefined', () => {
		// A digest-time partial that omits `v` — the field is simply not copied.
		const partial = { t: 'ixn', d: '#', i: 'AID', s: '0', p: 'P', a: [] };
		const ordered = toCanonicalEvent(partial);
		expect(Object.keys(ordered)).toEqual(['t', 'd', 'i', 's', 'p', 'a']);
		expect('v' in ordered).toBe(false);
	});

	test('drops fields that are not part of the canonical order', () => {
		const ordered = toCanonicalEvent({
			t: 'ixn',
			d: 'D',
			i: 'AID',
			s: '0',
			p: 'P',
			a: [],
			rogue: 'unexpected',
		});
		expect('rogue' in ordered).toBe(false);
	});

	test('rejects an event of unknown type', () => {
		expect(() => toCanonicalEvent({ t: 'xyz', d: 'D' })).toThrow(
			InvalidArgumentError
		);
	});

	test('rejects an event with a non-string type', () => {
		expect(() => toCanonicalEvent({ t: 1, d: 'D' })).toThrow(
			InvalidArgumentError
		);
		expect(() => toCanonicalEvent({ d: 'D' })).toThrow(InvalidArgumentError);
	});
});
