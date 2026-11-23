"use client";

import * as React from "react";
import {
  DEFAULT_PREFS,
  loadPrefs,
  savePrefs,
  type Preferences,
} from "@/lib/preferences";

type PreferencesCtx = {
  prefs: Preferences;
  update: (partial: Partial<Preferences>) => void;
};

const Ctx = React.createContext<PreferencesCtx | null>(null);

export function PreferencesProvider({ children }: { children: React.ReactNode }) {
  const [prefs, setPrefs] = React.useState<Preferences>(DEFAULT_PREFS);

  // 首帧从 localStorage 载入（SSR 阶段用默认值，避免 hydration 抖动）
  React.useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- 客户端挂载后同步浏览器持久化偏好，避免 SSR hydration 不一致。
    setPrefs(loadPrefs());
  }, []);

  const update = React.useCallback((partial: Partial<Preferences>) => {
    setPrefs((prev) => {
      const next = { ...prev, ...partial };
      savePrefs(next);
      return next;
    });
  }, []);

  // 字号作用到根元素，全局对话区读取
  React.useEffect(() => {
    if (typeof document !== "undefined") {
      document.documentElement.dataset.fontSize = prefs.fontSize;
    }
  }, [prefs.fontSize]);

  const value = React.useMemo(() => ({ prefs, update }), [prefs, update]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function usePreferences(): PreferencesCtx {
  const c = React.useContext(Ctx);
  if (!c) throw new Error("usePreferences 必须在 PreferencesProvider 内使用");
  return c;
}
