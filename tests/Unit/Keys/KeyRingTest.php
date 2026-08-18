<?php

declare(strict_types=1);

use Davmixcool\Cryptman\Exceptions\InvalidConfigurationException;
use Davmixcool\Cryptman\Keys\Key;
use Davmixcool\Cryptman\Keys\KeyRing;

it('encrypts with the current key', function () {
    $current = Key::fromUserInput('current');
    $ring = new KeyRing($current, [Key::fromUserInput('old')]);

    expect($ring->current())->toBe($current);
});

it('tries the current key first, then previous keys in order', function () {
    $current = Key::fromUserInput('current');
    $old1 = Key::fromUserInput('old-1');
    $old2 = Key::fromUserInput('old-2');

    expect((new KeyRing($current, [$old1, $old2]))->all())->toBe([$current, $old1, $old2]);
});

it('works with no previous keys', function () {
    $ring = new KeyRing(Key::fromUserInput('only'));

    expect($ring->all())->toHaveCount(1)
        ->and($ring->previous())->toBe([])
        ->and($ring->count())->toBe(1);
});

it('rejects non-Key entries in previous_keys', function () {
    expect(fn () => new KeyRing(Key::fromUserInput('current'), ['a-raw-string']))
        ->toThrow(InvalidConfigurationException::class);
});

it('reports the offending index when previous_keys is malformed', function () {
    try {
        new KeyRing(Key::fromUserInput('current'), [Key::fromUserInput('ok'), 'bad']);
        $this->fail('expected InvalidConfigurationException');
    } catch (InvalidConfigurationException $e) {
        expect($e->getMessage())->toContain('previous_keys[1]');
    }
});

it('normalises a sparse previous_keys array to a list', function () {
    $ring = new KeyRing(Key::fromUserInput('current'), [
        3 => Key::fromUserInput('old-1'),
        7 => Key::fromUserInput('old-2'),
    ]);

    expect(array_keys($ring->previous()))->toBe([0, 1]);
});

it('keeps key material out of debug output', function () {
    $ring = new KeyRing(Key::fromUserInput('current'), [Key::fromUserInput('old')]);
    $material = $ring->current()->material();

    expect(print_r($ring, true))->not->toContain($material)
        ->and(print_r($ring, true))->toContain('[redacted]');
});

it('wipes every key in the ring', function () {
    $current = Key::fromUserInput('current');
    $old = Key::fromUserInput('old');

    (new KeyRing($current, [$old]))->wipe();

    expect($current->isWiped())->toBeTrue()->and($old->isWiped())->toBeTrue();
});
