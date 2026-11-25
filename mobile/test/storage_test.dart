import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:v18/storage/card_store.dart';

import 'helpers/fakes.dart';

void main() {
  test('only the fields PROTOCOL 3.10 allows are stored', () async {
    final kv = MemoryKeyValueStore();
    final store = CardStore(kv);
    await store.saveCard(AgeCard(
        cardId: 'card_x',
        method: 'test_dev',
        validUntil: DateTime.utc(2027, 1, 1),
        keyAlias: 'v18_card_abc',
        server: 'http://localhost:8080'));
    final saved = jsonDecode(kv.data['card']!) as Map<String, dynamic>;
    expect(saved.keys.toSet(), {'cardId', 'method', 'validUntil', 'keyAlias', 'server'});
    expect((await store.loadCard())!.cardId, 'card_x');
  });

  test('shared-device mode: a new card is kept in memory only', () async {
    final server = FakeV18Server();
    final keys = FakeDeviceKeyService();
    final kv = MemoryKeyValueStore();
    final app = fakeAppState(server, keys, kv: kv);
    await app.load();
    await app.setSharedDevice(true);
    final info = await keys.createKey('v18_card_one');
    await app.saveCard(AgeCard(
        cardId: 'card_1',
        method: 'test_dev',
        validUntil: DateTime.now().add(const Duration(days: 1)),
        keyAlias: info.alias,
        server: testServer));
    expect(app.card, isNotNull);
    expect(kv.data.containsKey('card'), isFalse);

    // Next app start: nothing stored, keys wiped.
    final app2 = fakeAppState(server, keys, kv: kv);
    await app2.load();
    expect(app2.card, isNull);
    expect(keys.keys, isEmpty);
  });

  test('turning shared mode on removes a saved card from storage', () async {
    final server = FakeV18Server();
    final keys = FakeDeviceKeyService();
    final kv = MemoryKeyValueStore();
    final app = fakeAppState(server, keys, kv: kv);
    await app.load();
    await app.saveCard(AgeCard(
        cardId: 'card_1',
        method: 'test_dev',
        validUntil: DateTime.now().add(const Duration(days: 1)),
        keyAlias: 'v18_card_a',
        server: testServer));
    expect(kv.data.containsKey('card'), isTrue);
    await app.setSharedDevice(true);
    expect(kv.data.containsKey('card'), isFalse);
    expect(app.settings.sharedDevice, isTrue);
  });

  test('health tells the app about dev mode (TEST MODE banner)', () async {
    final app = fakeAppState(FakeV18Server(devMode: true), FakeDeviceKeyService());
    await app.load();
    expect(app.devMode, isTrue);
    final prod = fakeAppState(FakeV18Server(devMode: false), FakeDeviceKeyService());
    await prod.load();
    expect(prod.devMode, isFalse);
  });
}
