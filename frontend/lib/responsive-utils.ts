/**
 * Responsive utility constants and helper functions
 *
 * Breakpoints:
 * - xs: 475px (extra small screens)
 * - sm: 640px (small screens)
 * - md: 768px (medium screens/tablets)
 * - lg: 1024px (large screens/small desktops)
 * - xl: 1280px (extra large screens)
 * - 2xl: 1536px (2x extra large screens)
 */

export const RESPONSIVE_CLASSES = {
  // Grid classes for common layouts
  statsGrid: "grid grid-cols-1 xs:grid-cols-2 xl:grid-cols-4 gap-3 sm:gap-4",
  cardGrid:
    "grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3 sm:gap-4 md:gap-6",

  // Header visibility breakpoints
  mobileHeader: "block lg:hidden",
  desktopHeader: "hidden lg:flex",
  tabletHideUserInfo: "hidden xl:block",

  // Common responsive spacing
  containerPadding: "px-2 sm:px-4",
  sectionSpacing: "py-4 sm:py-6",
  cardSpacing: "mb-6 sm:mb-8",

  // Flex utilities
  responsiveFlex: "flex flex-col md:flex-row gap-3 md:gap-4 md:items-center",
  responsiveButtonGroup:
    "flex flex-col xs:flex-row md:flex-row items-stretch xs:items-center md:items-center gap-2 xs:gap-3 md:flex-shrink-0",
  flexNone: "flex-1 xs:flex-none md:flex-none",
} as const;

/**
 * Helper function to combine responsive classes with custom classes
 */
export function combineResponsiveClasses(
  responsiveClass: keyof typeof RESPONSIVE_CLASSES,
  customClasses: string = "",
): string {
  return `${RESPONSIVE_CLASSES[responsiveClass]} ${customClasses}`.trim();
}

/**
 * Get appropriate grid columns for different content types
 */
export function getGridColumns(type: "stats" | "cards" | "loading"): string {
  switch (type) {
    case "stats":
      return RESPONSIVE_CLASSES.statsGrid;
    case "cards":
    case "loading":
      return RESPONSIVE_CLASSES.cardGrid;
    default:
      return RESPONSIVE_CLASSES.cardGrid;
  }
}

/**
 * Get appropriate header classes for mobile/desktop visibility
 */
export function getHeaderClasses(type: "mobile" | "desktop"): string {
  return type === "mobile"
    ? RESPONSIVE_CLASSES.mobileHeader
    : RESPONSIVE_CLASSES.desktopHeader;
}
