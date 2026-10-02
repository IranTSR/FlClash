import 'dart:convert';
import 'dart:typed_data';

import 'package:yaml/yaml.dart' show loadYaml;

import 'yaml.dart';

/// Converts proxy share-links (vless://, vmess://, trojan://, ss://,
/// hy2://, tuic://, socks://, ...) and subscriptions made of those links into
/// a Clash.Meta compatible YAML config at import time. Unrecognized input is
/// returned untouched, so existing behavior never changes.
class ProxyLinkConverter {
  static const _proxySchemes = {
    'vless',
    'vmess',
    'trojan',
    'ss',
    'shadowsocks',
    'hy2',
    'hysteria2',
    'tuic',
    'socks',
    'socks5',
  };

  static bool isProxyLink(String input) {
    final match =
        RegExp(r'^([A-Za-z][A-Za-z0-9+.-]*)://').firstMatch(input.trim());
    if (match == null) return false;
    return _proxySchemes.contains(match.group(1)!.toLowerCase());
  }

  static String linkName(String input) {
    final uri = Uri.tryParse(input.trim());
    final fragment = uri?.fragment ?? '';
    if (fragment.isEmpty) return '';
    try {
      return Uri.decodeComponent(fragment);
    } catch (_) {
      return fragment;
    }
  }

  static Uint8List maybeConvertProfileBytes(Uint8List bytes) {
    final text = utf8.decode(bytes, allowMalformed: true).trim();
    if (text.isEmpty) return bytes;
    if (_looksLikeClashConfig(text)) return bytes;
    var candidate = text;
    final decoded = _tryBase64Decode(text);
    if (decoded != null) {
      if (_looksLikeClashConfig(decoded)) {
        return Uint8List.fromList(utf8.encode(decoded));
      }
      candidate = decoded;
    }
    final proxies = <Map<String, dynamic>>[];
    for (final line in candidate.split(RegExp(r'[\r\n]+'))) {
      final proxy = parseProxyLink(line.trim());
      if (proxy != null) proxies.add(proxy);
    }
    if (proxies.isEmpty) return bytes;
    _ensureUniqueNames(proxies);
    return Uint8List.fromList(utf8.encode(buildClashConfig(proxies)));
  }

  static Map<String, dynamic>? parseProxyLink(String link) {
    final text = link.trim();
    if (text.isEmpty) return null;
    final uri = Uri.tryParse(text);
    if (uri == null || !uri.hasScheme) return null;
    final name = linkName(text);
    switch (uri.scheme.toLowerCase()) {
      case 'vless':
        return _parseVless(uri, name);
      case 'vmess':
        return _parseVmess(text, name);
      case 'trojan':
        return _parseTrojan(uri, name);
      case 'ss':
      case 'shadowsocks':
        return _parseShadowsocks(uri, name);
      case 'hy2':
      case 'hysteria2':
        return _parseHysteria2(uri, name);
      case 'tuic':
        return _parseTuic(uri, name);
      case 'socks':
      case 'socks5':
        return _parseSocks(uri, name);
    }
    return null;
  }

  static String buildClashConfig(List<Map<String, dynamic>> proxies) {
    final names = proxies.map((p) => p['name'].toString()).toList();
    return yaml.encode({
      'proxies': proxies,
      'proxy-groups': [
        {
          'name': 'PROXY',
          'type': 'select',
          'proxies': names,
        },
      ],
      'rules': ['MATCH,PROXY'],
    });
  }

  static bool _looksLikeClashConfig(String text) {
    try {
      final doc = loadYaml(text);
      if (doc is! YamlMap) return false;
      return doc.containsKey('proxies') ||
          doc.containsKey('proxy-groups') ||
          doc.containsKey('rules');
    } catch (_) {
      return false;
    }
  }

  static String? _tryBase64Decode(String input) {
    final decoded = _rawBase64Decode(input);
    if (decoded == null) return null;
    if (!decoded.contains('://') && !_looksLikeClashConfig(decoded)) {
      return null;
    }
    return decoded;
  }

  static String? _rawBase64Decode(String input) {
    var s = input.replaceAll(RegExp(r'\s+'), '');
    if (s.length < 8) return null;
    if (!RegExp(r'^[A-Za-z0-9+/\-_]+={0,2}$').hasMatch(s)) return null;
    s = s.replaceAll('-', '+').replaceAll('_', '/');
    final mod = s.length % 4;
    if (mod == 1) return null;
    if (mod != 0) s += '=' * (4 - mod);
    try {
      return utf8.decode(base64.decode(s), allowMalformed: true);
    } catch (_) {
      return null;
    }
  }

  static String? _decodeBase64(String input) {
    return _rawBase64Decode(input);
  }

  static void _ensureUniqueNames(List<Map<String, dynamic>> proxies) {
    final seen = <String>{};
    for (final proxy in proxies) {
      var name = proxy['name'].toString();
      if (name.isEmpty) {
        name = '${proxy['type']}-${proxy['server']}';
      }
      var candidate = name;
      var i = 2;
      while (!seen.add(candidate)) {
        candidate = '$name $i';
        i++;
      }
      proxy['name'] = candidate;
    }
  }

  static int _port(Uri uri, [int fallback = 443]) {
    return uri.hasPort ? uri.port : fallback;
  }

  static bool _isTruthy(String? value) {
    return value == '1' || value?.toLowerCase() == 'true';
  }

  static String _defaultName(String name, String fallback) {
    return name.isNotEmpty ? name : fallback;
  }

  static String _clashNetwork(String type) {
    switch (type.toLowerCase()) {
      case 'tcp':
      case 'ws':
      case 'grpc':
      case 'http':
      case 'h2':
        return type.toLowerCase();
      default:
        return 'tcp';
    }
  }

  static void _applyStreamSettings(
    Map<String, dynamic> proxy,
    String network,
    Map<String, String> q,
    String defaultHost,
  ) {
    switch (network) {
      case 'ws':
        final headers = <String, dynamic>{};
        final host = q['host'];
        if (host != null && host.isNotEmpty) headers['Host'] = host;
        proxy['ws-opts'] = {
          'path': (q['path']?.isNotEmpty ?? false) ? q['path']! : '/',
          if (headers.isNotEmpty) 'headers': headers,
        };
      case 'grpc':
        proxy['grpc-opts'] = {
          'grpc-service-name': q['serviceName'] ?? q['path'] ?? '',
        };
      case 'h2':
        final host = q['host'];
        proxy['h2-opts'] = {
          'host': [host?.isNotEmpty ?? false ? host! : defaultHost],
          'path': (q['path']?.isNotEmpty ?? false) ? q['path']! : '/',
        };
      case 'http':
        proxy['http-opts'] = {
          'method': 'GET',
          'path': [(q['path']?.isNotEmpty ?? false) ? q['path']! : '/'],
        };
      case 'tcp':
        if ((q['headerType'] ?? '').toLowerCase() == 'http') {
          final host = q['host'];
          proxy['http-opts'] = {
            'method': 'GET',
            'path': [(q['path']?.isNotEmpty ?? false) ? q['path']! : '/'],
            'headers': {
              'Host': [
                host?.isNotEmpty ?? false ? host! : defaultHost,
              ],
            },
          };
        }
    }
  }

  static void _applyTls(
    Map<String, dynamic> proxy,
    Map<String, String> q,
    String defaultServerName,
  ) {
    proxy['tls'] = true;
    final sni = q['sni'];
    proxy['servername'] =
        (sni?.isNotEmpty ?? false) ? sni! : defaultServerName;
    final fp = q['fp'];
    if (fp != null && fp.isNotEmpty) proxy['client-fingerprint'] = fp;
    final alpn = q['alpn'];
    if (alpn != null && alpn.isNotEmpty) proxy['alpn'] = alpn.split(',');
    if (_isTruthy(q['allowInsecure'])) proxy['skip-cert-verify'] = true;
  }

  static Map<String, dynamic>? _parseVless(Uri uri, String name) {
    final q = uri.queryParameters;
    final uuid = uri.userInfo;
    if (uuid.isEmpty || uri.host.isEmpty) return null;
    final proxy = <String, dynamic>{
      'name': _defaultName(name, 'vless'),
      'type': 'vless',
      'server': uri.host,
      'port': _port(uri),
      'uuid': uuid,
      'udp': true,
    };
    final security = (q['security'] ?? 'none').toLowerCase();
    if (security == 'tls' || security == 'reality') {
      _applyTls(proxy, q, uri.host);
      if (security == 'reality') {
        proxy['reality-opts'] = {
          'public-key': q['pbk'] ?? '',
          'short-id': q['sid'] ?? '',
        };
      }
    }
    final flow = q['flow'];
    if (flow != null && flow.isNotEmpty) proxy['flow'] = flow;
    final network = _clashNetwork(q['type'] ?? 'tcp');
    proxy['network'] = network;
    _applyStreamSettings(proxy, network, q, uri.host);
    return proxy;
  }

  static Map<String, dynamic>? _parseVmess(String text, String name) {
    var payload = text.substring(text.indexOf('://') + 3).trim();
    final cut = payload.indexOf(RegExp(r'[#?]'));
    if (cut >= 0) payload = payload.substring(0, cut);
    final jsonStr = _decodeBase64(payload);
    if (jsonStr == null) return null;
    late final Map<String, dynamic> map;
    try {
      map = Map<String, dynamic>.from(jsonDecode(jsonStr) as Map);
    } catch (_) {
      return null;
    }
    final server = map['add']?.toString() ?? '';
    if (server.isEmpty) return null;
    final proxy = <String, dynamic>{
      'name': _defaultName(name, map['ps']?.toString() ?? 'vmess'),
      'type': 'vmess',
      'server': server,
      'port': int.tryParse(map['port']?.toString() ?? '') ?? 443,
      'uuid': map['id']?.toString() ?? '',
      'alterId': int.tryParse(map['aid']?.toString() ?? '') ?? 0,
      'cipher': (map['scy']?.toString().isNotEmpty ?? false)
          ? map['scy'].toString()
          : 'auto',
      'udp': true,
    };
    if ((map['tls']?.toString() ?? '').toLowerCase() == 'tls') {
      proxy['tls'] = true;
      final sni = map['sni']?.toString() ?? '';
      proxy['servername'] = sni.isNotEmpty ? sni : server;
      final fp = map['fp']?.toString() ?? '';
      if (fp.isNotEmpty) proxy['client-fingerprint'] = fp;
      final alpn = map['alpn']?.toString() ?? '';
      if (alpn.isNotEmpty) proxy['alpn'] = alpn.split(',');
    }
    final network = _clashNetwork(map['net']?.toString() ?? 'tcp');
    proxy['network'] = network;
    _applyStreamSettings(
      proxy,
      network,
      {
        'path': map['path']?.toString() ?? '',
        'host': map['host']?.toString() ?? '',
        if ((map['type']?.toString() ?? '') == 'http') 'headerType': 'http',
      },
      server,
    );
    return proxy;
  }

  static Map<String, dynamic>? _parseTrojan(Uri uri, String name) {
    final q = uri.queryParameters;
    final password = uri.userInfo;
    if (password.isEmpty || uri.host.isEmpty) return null;
    final proxy = <String, dynamic>{
      'name': _defaultName(name, 'trojan'),
      'type': 'trojan',
      'server': uri.host,
      'port': _port(uri),
      'password': password,
      'udp': true,
    };
    // Trojan is always TLS.
    _applyTls(proxy, q, uri.host);
    final network = _clashNetwork(q['type'] ?? 'tcp');
    proxy['network'] = network;
    _applyStreamSettings(proxy, network, q, uri.host);
    return proxy;
  }

  static Map<String, dynamic>? _parseShadowsocks(Uri uri, String name) {
    var method = '';
    var password = '';
    var host = uri.host;
    var port = uri.hasPort ? uri.port : 0;
    final userInfo = uri.userInfo;
    if (userInfo.contains(':')) {
      method = userInfo.substring(0, userInfo.indexOf(':'));
      password = userInfo.substring(userInfo.indexOf(':') + 1);
    } else if (userInfo.isNotEmpty) {
      final decoded = _decodeBase64(userInfo);
      if (decoded == null || !decoded.contains(':')) return null;
      if (decoded.contains('@')) {
        final inner = Uri.tryParse('ss://$decoded');
        if (inner == null || inner.userInfo.isEmpty) return null;
        method = inner.userInfo.substring(0, inner.userInfo.indexOf(':'));
        password =
            inner.userInfo.substring(inner.userInfo.indexOf(':') + 1);
        host = inner.host;
        port = inner.hasPort ? inner.port : 0;
      } else {
        method = decoded.substring(0, decoded.indexOf(':'));
        password = decoded.substring(decoded.indexOf(':') + 1);
      }
    } else {
      return null;
    }
    if (method.isEmpty || host.isEmpty || port == 0) return null;
    final proxy = <String, dynamic>{
      'name': _defaultName(name, 'ss'),
      'type': 'ss',
      'server': host,
      'port': port,
      'cipher': method,
      'password': password,
      'udp': true,
    };
    final plugin = uri.queryParameters['plugin'];
    if (plugin != null && plugin.isNotEmpty) {
      final parts = plugin.split(';');
      final opts = <String, dynamic>{};
      for (final part in parts.skip(1)) {
        if (part == 'tls') {
          opts['tls'] = true;
          continue;
        }
        final kv = part.split('=');
        if (kv.length != 2) continue;
        final key = kv[0] == 'obfs-host'
            ? 'host'
            : kv[0] == 'obfs'
                ? 'mode'
                : kv[0];
        opts[key] = kv[1];
      }
      proxy['plugin'] = parts.first;
      if (opts.isNotEmpty) proxy['plugin-opts'] = opts;
    }
    return proxy;
  }

  static Map<String, dynamic>? _parseHysteria2(Uri uri, String name) {
    final q = uri.queryParameters;
    final password = uri.userInfo;
    if (password.isEmpty || uri.host.isEmpty) return null;
    final proxy = <String, dynamic>{
      'name': _defaultName(name, 'hysteria2'),
      'type': 'hysteria2',
      'server': uri.host,
      'port': _port(uri),
      'password': password,
      'sni': (q['sni']?.isNotEmpty ?? false) ? q['sni']! : uri.host,
      'skip-cert-verify': _isTruthy(q['insecure']),
    };
    final obfs = q['obfs'];
    if (obfs != null && obfs.isNotEmpty) {
      proxy['obfs'] = obfs;
      proxy['obfs-password'] = q['obfs-password'] ?? '';
    }
    final up = q['up'];
    if (up != null && up.isNotEmpty) proxy['up'] = up;
    final down = q['down'];
    if (down != null && down.isNotEmpty) proxy['down'] = down;
    return proxy;
  }

  static Map<String, dynamic>? _parseTuic(Uri uri, String name) {
    final q = uri.queryParameters;
    final userInfo = uri.userInfo;
    if (userInfo.isEmpty || uri.host.isEmpty) return null;
    final parts = userInfo.split(':');
    final proxy = <String, dynamic>{
      'name': _defaultName(name, 'tuic'),
      'type': 'tuic',
      'server': uri.host,
      'port': _port(uri),
      'uuid': parts.first,
      'password': parts.length > 1 ? parts.sublist(1).join(':') : '',
      'udp': true,
      'sni': (q['sni']?.isNotEmpty ?? false) ? q['sni']! : uri.host,
      'alpn': ((q['alpn']?.isNotEmpty ?? false) ? q['alpn']! : 'h3')
          .split(','),
      'congestion-controller': q['congestion_control'] ?? 'bbr',
      'udp-relay-mode': q['udp_relay_mode'] ?? 'native',
      'skip-cert-verify': _isTruthy(q['allow_insecure']),
    };
    return proxy;
  }

  static Map<String, dynamic>? _parseSocks(Uri uri, String name) {
    if (uri.host.isEmpty) return null;
    final q = uri.queryParameters;
    final userInfo = uri.userInfo;
    final proxy = <String, dynamic>{
      'name': _defaultName(name, 'socks5'),
      'type': 'socks5',
      'server': uri.host,
      'port': _port(uri, 1080),
      'udp': true,
    };
    if (userInfo.contains(':')) {
      proxy['username'] = userInfo.substring(0, userInfo.indexOf(':'));
      proxy['password'] = userInfo.substring(userInfo.indexOf(':') + 1);
    } else if (userInfo.isNotEmpty) {
      proxy['username'] = userInfo;
    }
    if (_isTruthy(q['tls'])) {
      proxy['tls'] = true;
      proxy['sni'] =
          (q['sni']?.isNotEmpty ?? false) ? q['sni']! : uri.host;
    }
    return proxy;
  }
}
