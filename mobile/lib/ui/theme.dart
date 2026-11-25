import 'package:flutter/material.dart';

/// Colour tokens from the V18 design mock-ups (light and dark).
class V18Tokens {
  const V18Tokens._();

  static const light = ColorScheme(
    brightness: Brightness.light,
    primary: Color(0xFF006A60),
    onPrimary: Color(0xFFFFFFFF),
    primaryContainer: Color(0xFF9EF2E4),
    onPrimaryContainer: Color(0xFF00201C),
    secondary: Color(0xFF4A635F),
    onSecondary: Color(0xFFFFFFFF),
    secondaryContainer: Color(0xFFCCE8E2),
    onSecondaryContainer: Color(0xFF051F1C),
    tertiary: Color(0xFF456179),
    onTertiary: Color(0xFFFFFFFF),
    tertiaryContainer: Color(0xFFD0E4FF),
    onTertiaryContainer: Color(0xFF001D35),
    error: Color(0xFFBA1A1A),
    onError: Color(0xFFFFFFFF),
    errorContainer: Color(0xFFFFDAD6),
    onErrorContainer: Color(0xFF410002),
    surface: Color(0xFFF4FBF8),
    onSurface: Color(0xFF161D1C),
    onSurfaceVariant: Color(0xFF3F4947),
    outline: Color(0xFF6F7977),
    outlineVariant: Color(0xFFBEC9C6),
    surfaceContainerLowest: Color(0xFFFFFFFF),
    surfaceContainerLow: Color(0xFFEEF5F2),
    surfaceContainer: Color(0xFFE8EFEC),
    surfaceContainerHigh: Color(0xFFE2E9E6),
    surfaceContainerHighest: Color(0xFFDCE4E1),
    inverseSurface: Color(0xFF2B3230),
    onInverseSurface: Color(0xFFECF2EF),
    inversePrimary: Color(0xFF82D5C8),
  );

  static const dark = ColorScheme(
    brightness: Brightness.dark,
    primary: Color(0xFF82D5C8),
    onPrimary: Color(0xFF003731),
    primaryContainer: Color(0xFF005048),
    onPrimaryContainer: Color(0xFF9EF2E4),
    secondary: Color(0xFFB1CCC6),
    onSecondary: Color(0xFF1C3531),
    secondaryContainer: Color(0xFF334B47),
    onSecondaryContainer: Color(0xFFCCE8E2),
    tertiary: Color(0xFFADCAE6),
    onTertiary: Color(0xFF153349),
    tertiaryContainer: Color(0xFF2C4A64),
    onTertiaryContainer: Color(0xFFD0E4FF),
    error: Color(0xFFFFB4AB),
    onError: Color(0xFF690005),
    errorContainer: Color(0xFF93000A),
    onErrorContainer: Color(0xFFFFDAD6),
    surface: Color(0xFF0E1513),
    onSurface: Color(0xFFDDE4E1),
    onSurfaceVariant: Color(0xFFBEC9C6),
    outline: Color(0xFF899390),
    outlineVariant: Color(0xFF3F4947),
    surfaceContainerLowest: Color(0xFF090F0E),
    surfaceContainerLow: Color(0xFF161D1C),
    surfaceContainer: Color(0xFF1A2120),
    surfaceContainerHigh: Color(0xFF252B2A),
    surfaceContainerHighest: Color(0xFF2F3635),
    inverseSurface: Color(0xFFDDE4E1),
    onInverseSurface: Color(0xFF2B3230),
    inversePrimary: Color(0xFF006A60),
  );
}

/// The design's warning colours (--wc / --owc), used for "Weaker" and TEST labels.
class V18Colors extends ThemeExtension<V18Colors> {
  const V18Colors({required this.warningContainer, required this.onWarningContainer});

  final Color warningContainer;
  final Color onWarningContainer;

  static const light = V18Colors(
      warningContainer: Color(0xFFFFDDB3), onWarningContainer: Color(0xFF2A1800));
  static const dark = V18Colors(
      warningContainer: Color(0xFF5C4100), onWarningContainer: Color(0xFFFFDDB3));

  static V18Colors of(BuildContext context) =>
      Theme.of(context).extension<V18Colors>() ?? light;

  @override
  V18Colors copyWith({Color? warningContainer, Color? onWarningContainer}) => V18Colors(
        warningContainer: warningContainer ?? this.warningContainer,
        onWarningContainer: onWarningContainer ?? this.onWarningContainer,
      );

  @override
  V18Colors lerp(V18Colors? other, double t) => other == null
      ? this
      : V18Colors(
          warningContainer: Color.lerp(warningContainer, other.warningContainer, t)!,
          onWarningContainer: Color.lerp(onWarningContainer, other.onWarningContainer, t)!,
        );
}

ThemeData v18Theme(Brightness brightness) {
  final scheme = brightness == Brightness.light ? V18Tokens.light : V18Tokens.dark;
  final base = ThemeData(colorScheme: scheme, useMaterial3: true);
  return base.copyWith(
    scaffoldBackgroundColor: scheme.surface,
    extensions: [brightness == Brightness.light ? V18Colors.light : V18Colors.dark],
    appBarTheme: AppBarTheme(
      backgroundColor: scheme.surface,
      surfaceTintColor: Colors.transparent,
      elevation: 0,
      foregroundColor: scheme.onSurface,
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        minimumSize: const Size(64, 52),
        shape: const StadiumBorder(),
        textStyle: const TextStyle(fontSize: 16, fontWeight: FontWeight.w500),
      ),
    ),
    textButtonTheme: TextButtonThemeData(
      style: TextButton.styleFrom(
        // Not Size.fromHeight: an infinite minimum width breaks inside a Row.
        minimumSize: const Size(64, 48),
        shape: const StadiumBorder(),
        textStyle: const TextStyle(fontSize: 15, fontWeight: FontWeight.w500),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        minimumSize: const Size(64, 52),
        shape: const StadiumBorder(),
      ),
    ),
    // copyWith on Material's own styles keeps their colours. (New TextStyles
    // without a colour made headings nearly invisible on a real phone.)
    textTheme: base.textTheme.copyWith(
      headlineLarge: base.textTheme.headlineLarge!
          .copyWith(fontSize: 36, height: 44 / 36, fontWeight: FontWeight.w400, color: scheme.onSurface),
      headlineMedium: base.textTheme.headlineMedium!
          .copyWith(fontSize: 28, height: 36 / 28, fontWeight: FontWeight.w400, color: scheme.onSurface),
      bodyMedium: base.textTheme.bodyMedium!.copyWith(fontSize: 14, height: 20 / 14, color: scheme.onSurface),
    ),
  );
}
