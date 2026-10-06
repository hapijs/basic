import { describe, expect, it } from 'vitest';

describe('import()', () => {
    it('exposes all methods and classes as named imports', async () => {
        const Basic = await import('../src/index.js');

        expect(Object.keys(Basic)).toStrictEqual(['plugin']);
    });
});
