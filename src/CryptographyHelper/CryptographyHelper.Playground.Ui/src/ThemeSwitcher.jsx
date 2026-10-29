import { useEffect, useState } from 'react';
import { Sun, Moon, Monitor } from 'lucide-react';

const storageKey = 'cryptographyhelper-theme';
const themes = [
  { value: 'light', label: 'Light', Icon: Sun },
  { value: 'dark', label: 'Dark', Icon: Moon },
  { value: 'system', label: 'System', Icon: Monitor },
];
const validTheme = value => themes.some(theme => theme.value === value) ? value : 'system';

export default function ThemeSwitcher() {
  const [theme, setTheme] = useState(() => validTheme(document.documentElement.dataset.themePreference));

  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    function applyTheme() {
      document.documentElement.dataset.themePreference = theme;
      document.documentElement.dataset.theme = theme === 'system' ? (media.matches ? 'dark' : 'light') : theme;
    }
    applyTheme();
    media.addEventListener('change', applyTheme);
    return () => media.removeEventListener('change', applyTheme);
  }, [theme]);

  useEffect(() => {
    function syncTheme(event) {
      if (event.key === storageKey || event.key === null) setTheme(validTheme(event.newValue));
    }
    window.addEventListener('storage', syncTheme);
    return () => window.removeEventListener('storage', syncTheme);
  }, []);

  function chooseTheme(value) {
    setTheme(value);
    try { localStorage.setItem(storageKey, value); } catch { /* Still works when storage is unavailable. */ }
  }

  return <div className="theme-switcher" role="group" aria-label="Color theme">
    {themes.map(({ value, label, Icon }) => <button key={value} type="button" title={`${label} theme`} aria-label={`${label} theme`} aria-pressed={theme === value} onClick={() => chooseTheme(value)}>
      <Icon size={15} aria-hidden="true"/><span>{label}</span>
    </button>)}
  </div>;
}
