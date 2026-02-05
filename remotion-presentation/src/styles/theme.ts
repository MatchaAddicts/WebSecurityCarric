// Theme configuration based on the slide templates
export const theme = {
  colors: {
    primary: '#006080',      // Teal/dark cyan from header
    secondary: '#004d66',    // Darker teal
    accent: '#00a0c0',       // Lighter accent
    background: '#ffffff',
    text: '#333333',
    textLight: '#666666',
    textMuted: '#999999',
    tableHeader: '#006080',
    tableRowEven: '#f5f5f5',
    tableRowOdd: '#e8e8e8',
    warning: '#cc0000',      // Red for warnings/important text
    success: '#28a745',
  },
  fonts: {
    primary: 'Arial, Helvetica, sans-serif',
    heading: 'Arial, Helvetica, sans-serif',
  },
  spacing: {
    xs: 8,
    sm: 16,
    md: 24,
    lg: 48,
    xl: 80,
  },
  fontSize: {
    small: 24,
    body: 32,
    subtitle: 40,
    title: 72,
    heading: 96,
  },
};

export const slideStyles = {
  container: {
    width: '100%',
    height: '100%',
    backgroundColor: theme.colors.background,
    fontFamily: theme.fonts.primary,
    padding: theme.spacing.lg,
    display: 'flex',
    flexDirection: 'column' as const,
    position: 'relative' as const,
  },
  footer: {
    position: 'absolute' as const,
    bottom: theme.spacing.md,
    left: 0,
    right: 0,
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: `0 ${theme.spacing.lg}px`,
    color: theme.colors.textMuted,
    fontSize: theme.fontSize.small,
  },
};
