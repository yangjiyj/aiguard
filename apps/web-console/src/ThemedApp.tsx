import React, { useMemo } from 'react'
import { ConfigProvider, theme as antTheme } from 'antd'
// 必须用 ESM 语言包：antd/locale/zh_CN 是 CommonJS 转发，生产打包后默认导入变成 { default }，
// ConfigProvider 拿不到中文，分页显示“20 / page”、空表显示英文。
import zhCN from 'antd/es/locale/zh_CN'
import App from './App'
import { useThemeStore } from './stores/theme'

function ThemedApp() {
  const isDark = useThemeStore((s) => s.isDark)

  React.useEffect(() => {
    const root = document.documentElement
    root.setAttribute('data-theme', isDark ? 'dark' : 'light')
  }, [isDark])

  const themeConfig = useMemo(
    () => ({
      algorithm: (token: Parameters<typeof antTheme.defaultAlgorithm>[0]) => ({
        ...(isDark ? antTheme.darkAlgorithm(token) : antTheme.defaultAlgorithm(token)),
        colorPrimary: token.colorPrimary,
        colorSuccess: token.colorSuccess,
        colorWarning: token.colorWarning,
        colorError: token.colorError,
        colorInfo: token.colorInfo,
      }),
      token: {
        colorPrimary: isDark ? '#91b8ff' : '#245fc7',
        colorSuccess: isDark ? '#8bd3b7' : '#18765e',
        colorWarning: isDark ? '#eac185' : '#95601b',
        colorError: isDark ? '#f0a0a0' : '#b34444',
        colorInfo: isDark ? '#91b8ff' : '#245fc7',
        borderRadius: 6,
        fontFamily:
          "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', 'Helvetica Neue', Helvetica, Arial, sans-serif",
        fontSize: 14,
        colorBgContainer: isDark ? '#1b2029' : '#ffffff',
        colorBgLayout: isDark ? '#13171e' : '#f5f7fa',
        colorBgElevated: isDark ? '#222936' : '#f0f3f8',
        colorBorder: isDark ? '#303948' : '#e0e5ec',
        colorBorderSecondary: isDark ? '#303948' : '#e0e5ec',
        colorText: isDark ? '#e7edf7' : '#1e293b',
        colorTextSecondary: isDark ? '#a0adbf' : '#65748b',
        colorTextTertiary: isDark ? 'rgba(255,255,255,0.35)' : 'rgba(0,0,0,0.35)',
        colorTextQuaternary: isDark ? 'rgba(255,255,255,0.25)' : 'rgba(0,0,0,0.25)',
      },
      components: {
        Layout: {
          siderBg: isDark ? '#1b2029' : '#ffffff',
          headerBg: isDark ? '#1b2029' : '#ffffff',
          bodyBg: isDark ? '#13171e' : '#f5f7fa',
        },
        Menu: {
          darkItemBg: '#1b2029',
          darkPopupBg: '#222936',
          darkItemSelectedBg: '#233654',
          darkItemHoverBg: '#222936',
          darkItemSelectedColor: '#91b8ff',
          darkItemColor: '#a0adbf',
          darkItemHoverColor: '#e7edf7',
          itemSelectedBg: '#eaf1ff',
          itemSelectedColor: '#245fc7',
          itemHoverBg: '#f0f3f8',
          itemBorderRadius: 6,
          itemMarginInline: 0,
          itemHeight: 44,
          horizontalItemSelectedBg: 'transparent',
          darkHorizontalItemSelectedBg: 'transparent',
        },
        Button: {
          borderRadius: 6,
          controlHeight: 36,
          controlHeightLG: 40,
          colorPrimary: '#2862ce',
          colorPrimaryHover: '#2155b6',
          colorPrimaryActive: '#1b469b',
          primaryColor: '#ffffff',
        },
        Card: {
          borderRadiusLG: 8,
          paddingLG: 22,
          colorBgContainer: isDark ? '#1b2029' : '#ffffff',
        },
        Table: {
          borderRadiusLG: 8,
          headerBg: isDark ? '#222936' : '#f0f3f8',
          colorBgContainer: isDark ? '#1b2029' : '#ffffff',
          rowHoverBg: isDark ? '#222936' : '#f0f3f8',
          cellPaddingBlockSM: 10,
          cellPaddingInlineSM: 12,
        },
        Input: {
          borderRadius: 6,
          controlHeight: 36,
          colorBgContainer: isDark ? '#1b2029' : '#ffffff',
        },
        Select: {
          borderRadius: 6,
          controlHeight: 36,
          colorBgContainer: isDark ? '#1b2029' : '#ffffff',
        },
        Modal: {
          borderRadiusLG: 6,
        },
        Statistic: {
          contentFontSize: 29,
          titleFontSize: 13,
        },
        Tabs: {
          colorBgContainer: isDark ? '#1b2029' : '#ffffff',
        },
        Tag: {
          borderRadiusSM: 6,
        },
        Dropdown: {
          colorBgElevated: isDark ? '#222936' : '#f0f3f8',
        },
      },
    }),
    [isDark],
  )

  return (
    <ConfigProvider locale={zhCN} theme={themeConfig}>
      <App />
    </ConfigProvider>
  )
}

export default ThemedApp
