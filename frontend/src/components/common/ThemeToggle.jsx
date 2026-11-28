import React, { useEffect, useState } from 'react';
import Icon from './Icon';
import { THEME_EVENT, chooseTheme, currentTheme } from '../../utils/theme';

/** One button that switches between the light and dark sea. */
export default function ThemeToggle({ className = '' }) {
  const [theme, setTheme] = useState(currentTheme);

  useEffect(() => {
    const sync = () => setTheme(currentTheme());
    window.addEventListener(THEME_EVENT, sync);
    return () => window.removeEventListener(THEME_EVENT, sync);
  }, []);

  const next = theme === 'dark' ? 'light' : 'dark';
  return (
    <button type="button" className={`theme-toggle ${className}`} onClick={() => chooseTheme(next)}
      aria-label={`Switch to ${next} mode`} title={`Switch to ${next} mode`}>
      <Icon name={next === 'dark' ? 'moon' : 'sun'} size={17} />
    </button>
  );
}
