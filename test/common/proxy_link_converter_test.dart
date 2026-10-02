import 'dart:convert';
import 'dart:typed_data';

import 'package:fl_clash/common/proxy_link_converter.dart';
import 'package:test/test.dart';
import 'package:yaml/yaml.dart' show loadYaml;

void main() {
  group('isProxyLink', () {
    test('accepts known proxy schemes', () {
      expect(ProxyLinkConverter.isProxyLink('vless://a@b:1'), isTrue);
      expect(
        ProxyLinkConverter.isProxyLink(
          'vmess://${base64Encode(utf8.encode('{"v":"2"}'))}',
        ),
        isTrue,
      );
      expect(ProxyLinkConverter.isProxyLink('trojan://p@b:1'), isTrue);
      expect(ProxyLinkConverter.isProxyLink('ss://bWV0aDpwYXNz@b:1'), isTrue);
      expect(ProxyLinkConverter.isProxyLink('hy2://p@b:1'), isTrue);
      expect(ProxyLinkConverter.isProxyLink('tuic://u:p@b:1'), isTrue);
      expect(ProxyLinkConverter.isProxyLink('socks5://b:1'), isTrue);
    });

    test('rejects urls and garbage', () {
      expect(ProxyLinkConverter.isProxyLink('https://a/b'), isFalse);
      expect(ProxyLinkConverter.isProxyLink('proxies:\n  - a'), isFalse);
      expect(ProxyLinkConverter.isProxyLink('not a link'), isFalse);
      expect(ProxyLinkConverter.isProxyLink(''), isFalse);
    });
  });

  group('parseProxyLink', () {
    test('vless with ws and tls', () {
      final proxy = ProxyLinkConverter.parseProxyLink(
        'vless://11111111-2222-3333-4444-555555555555@example.com:443'
        '?encryption=none&security=tls&sni=example.com&fp=chrome'
        '&type=ws&path=%2Fws&host=example.com#Test%20VLESS',
      )!;
      expect(proxy['type'], 'vless');
      expect(proxy['server'], 'example.com');
      expect(proxy['port'], 443);
      expect(proxy['uuid'], '11111111-2222-3333-4444-555555555555');
      expect(proxy['tls'], isTrue);
      expect(proxy['servername'], 'example.com');
      expect(proxy['client-fingerprint'], 'chrome');
      expect(proxy['network'], 'ws');
      expect(proxy['ws-opts']['path'], '/ws');
      expect(proxy['ws-opts']['headers']['Host'], 'example.com');
      expect(proxy['name'], 'Test VLESS');
    });

    test('vless with reality', () {
      final proxy = ProxyLinkConverter.parseProxyLink(
        'vless://11111111-2222-3333-4444-555555555555@example.com:443'
        '?encryption=none&security=reality&sni=example.com&fp=chrome'
        '&pbk=PUBKEY&sid=abcd&flow=xtls-rprx-vision#Reality',
      )!;
      expect(proxy['tls'], isTrue);
      expect(proxy['flow'], 'xtls-rprx-vision');
      expect(proxy['reality-opts']['public-key'], 'PUBKEY');
      expect(proxy['reality-opts']['short-id'], 'abcd');
    });

    test('vmess from base64 json', () {
      final json = jsonEncode({
        'v': '2',
        'ps': 'VMESS',
        'add': 'vmess.example.com',
        'port': '443',
        'id': '22222222-3333-4444-5555-666666666666',
        'aid': '0',
        'scy': 'auto',
        'net': 'ws',
        'type': 'none',
        'host': 'vmess.example.com',
        'path': '/vm',
        'tls': 'tls',
        'sni': 'vmess.example.com',
      });
      final link = 'vmess://${base64Encode(utf8.encode(json))}';
      final proxy = ProxyLinkConverter.parseProxyLink(link)!;
      expect(proxy['type'], 'vmess');
      expect(proxy['server'], 'vmess.example.com');
      expect(proxy['uuid'], '22222222-3333-4444-5555-666666666666');
      expect(proxy['alterId'], 0);
      expect(proxy['tls'], isTrue);
      expect(proxy['network'], 'ws');
      expect(proxy['name'], 'VMESS');
    });

    test('trojan with ws', () {
      final proxy = ProxyLinkConverter.parseProxyLink(
        'trojan://secret@example.com:443?sni=example.com'
        '&type=ws&path=%2Ftr#Trojan',
      )!;
      expect(proxy['type'], 'trojan');
      expect(proxy['password'], 'secret');
      expect(proxy['tls'], isTrue);
      expect(proxy['sni'] ?? proxy['servername'], isNotNull);
      expect(proxy['network'], 'ws');
      expect(proxy['name'], 'Trojan');
    });

    test('shadowsocks plain and encoded forms', () {
      final plain = ProxyLinkConverter.parseProxyLink(
        'ss://aes-128-gcm:pass123@example.com:8388#SS',
      )!;
      expect(plain['cipher'], 'aes-128-gcm');
      expect(plain['password'], 'pass123');
      expect(plain['port'], 8388);

      final encoded = ProxyLinkConverter.parseProxyLink(
        'ss://YWVzLTEyOC1nY206cGFzczEyMw@example.com:8388#SS2',
      )!;
      expect(encoded['cipher'], 'aes-128-gcm');
      expect(encoded['password'], 'pass123');

      final full = ProxyLinkConverter.parseProxyLink(
        'ss://${base64Encode(utf8.encode('chacha20-ietf:pw@example.com:9999'))}#SS3',
      )!;
      expect(full['cipher'], 'chacha20-ietf');
      expect(full['server'], 'example.com');
      expect(full['port'], 9999);
    });

    test('hysteria2', () {
      final proxy = ProxyLinkConverter.parseProxyLink(
        'hy2://pass@example.com:443?sni=example.com&insecure=1'
        '&obfs=salamander&obfs-password=obf#HY2',
      )!;
      expect(proxy['type'], 'hysteria2');
      expect(proxy['password'], 'pass');
      expect(proxy['obfs'], 'salamander');
      expect(proxy['obfs-password'], 'obf');
      expect(proxy['skip-cert-verify'], isTrue);
    });

    test('tuic', () {
      final proxy = ProxyLinkConverter.parseProxyLink(
        'tuic://11111111-2222-3333-4444-555555555555:pass@example.com:443'
        '?sni=example.com&alpn=h3&congestion_control=bbr#TUIC',
      )!;
      expect(proxy['type'], 'tuic');
      expect(proxy['uuid'], '11111111-2222-3333-4444-555555555555');
      expect(proxy['password'], 'pass');
      expect(proxy['congestion-controller'], 'bbr');
    });

    test('socks5 with auth', () {
      final proxy = ProxyLinkConverter.parseProxyLink(
        'socks5://user:pw@example.com:1080#SOCKS',
      )!;
      expect(proxy['type'], 'socks5');
      expect(proxy['username'], 'user');
      expect(proxy['password'], 'pw');
    });

    test('returns null for invalid links', () {
      expect(ProxyLinkConverter.parseProxyLink('vless://'), isNull);
      expect(ProxyLinkConverter.parseProxyLink('https://a/b'), isNull);
      expect(ProxyLinkConverter.parseProxyLink('vmess://!!!'), isNull);
      expect(ProxyLinkConverter.parseProxyLink('unknown://a@b:1'), isNull);
    });
  });

  group('maybeConvertProfileBytes', () {
    test('passes clash yaml through untouched', () {
      final config = 'proxies:\n  - name: a\n    type: ss\nrules:\n  - MATCH,DIRECT\n';
      final bytes = Uint8List.fromList(utf8.encode(config));
      expect(ProxyLinkConverter.maybeConvertProfileBytes(bytes), bytes);
    });

    test('converts a single link into a full config', () {
      final link = 'trojan://secret@example.com:443?sni=example.com#T1';
      final out = ProxyLinkConverter.maybeConvertProfileBytes(
        Uint8List.fromList(utf8.encode(link)),
      );
      final doc = loadYaml(utf8.decode(out)) as YamlMap;
      expect((doc['proxies'] as YamlList).length, 1);
      expect((doc['proxies'] as YamlList).first['type'], 'trojan');
      expect((doc['proxy-groups'] as YamlList).first['name'], 'PROXY');
      expect((doc['rules'] as YamlList).first, 'MATCH,PROXY');
    });

    test('converts multi-line link lists and dedupes names', () {
      final input = 'ss://aes-128-gcm:p1@a.com:1#Same\n'
          'ss://aes-128-gcm:p2@b.com:2#Same\n'
          'not-a-link\n';
      final out = ProxyLinkConverter.maybeConvertProfileBytes(
        Uint8List.fromList(utf8.encode(input)),
      );
      final doc = loadYaml(utf8.decode(out)) as YamlMap;
      final proxies = doc['proxies'] as YamlList;
      expect(proxies.length, 2);
      expect(proxies[0]['name'], 'Same');
      expect(proxies[1]['name'], 'Same 2');
    });

    test('decodes base64 subscriptions', () {
      final sub = 'vless://11111111-2222-3333-4444-555555555555@a.com:443#A\n'
          'ss://aes-128-gcm:pw@b.com:8388#B\n';
      final encoded = base64Encode(utf8.encode(sub));
      final out = ProxyLinkConverter.maybeConvertProfileBytes(
        Uint8List.fromList(utf8.encode(encoded)),
      );
      final doc = loadYaml(utf8.decode(out)) as YamlMap;
      expect((doc['proxies'] as YamlList).length, 2);
    });

    test('decodes base64-encoded clash yaml', () {
      final config = 'proxies:\n  - name: a\nrules:\n  - MATCH,DIRECT\n';
      final encoded = base64Encode(utf8.encode(config));
      final out = ProxyLinkConverter.maybeConvertProfileBytes(
        Uint8List.fromList(utf8.encode(encoded)),
      );
      expect(utf8.decode(out), config);
    });

    test('returns garbage untouched', () {
      final bytes = Uint8List.fromList(utf8.encode('hello world'));
      expect(ProxyLinkConverter.maybeConvertProfileBytes(bytes), bytes);
      expect(
        ProxyLinkConverter.maybeConvertProfileBytes(Uint8List(0)).length,
        0,
      );
    });
  });
}
