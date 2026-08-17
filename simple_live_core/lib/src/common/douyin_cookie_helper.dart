class DouyinCookieHelper {
  static bool hasCustomCookie(String cookie) {
    return cookie.trim().isNotEmpty;
  }

  static bool isOnlyTtwid(String cookie) {
    final normalized = cookie.trim().toLowerCase();
    return normalized.startsWith("ttwid=") && !normalized.contains(";");
  }

  static bool hasFullCookie(String cookie) {
    final normalized = cookie.trim();
    return normalized.isNotEmpty && !isOnlyTtwid(normalized);
  }

  static String normalizeInput(String input) {
    var cookie = extractCookieFromHeaderText(input) ?? input.trim();
    if (cookie.toLowerCase().startsWith("cookie:")) {
      cookie = cookie.substring(cookie.indexOf(":") + 1).trim();
    }
    if (!cookie.contains("=")) {
      cookie = 'ttwid=$cookie';
    }
    return cookie;
  }

  static String? extractCookieFromHeaderText(String input) {
    final lines = input
        .split(RegExp(r"\r?\n"))
        .map((line) => line.trim())
        .where((line) => line.isNotEmpty)
        .toList();

    for (var i = 0; i < lines.length; i++) {
      final line = lines[i];
      final lower = line.toLowerCase();
      if (lower.startsWith("cookie:")) {
        return line.substring(line.indexOf(":") + 1).trim();
      }
      if (lower == "cookie" && i + 1 < lines.length) {
        return lines[i + 1].trim();
      }
    }
    return null;
  }
}
