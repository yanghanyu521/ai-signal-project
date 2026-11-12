import React from 'react';
import ReactDOM from 'react-dom/client';
import { HashRouter } from 'react-router-dom';
import { ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import App from './App';
import './app.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider
      locale={zhCN}
      theme={{
        token: {
          colorPrimary: '#4F46E5',
          colorInfo: '#4F46E5',
          colorSuccess: '#16A34A',
          colorWarning: '#D97706',
          colorError: '#DC2626',
          borderRadius: 8,
          borderRadiusLG: 12,
          fontSize: 14,
          colorText: '#111827',
          colorTextSecondary: '#6B7280',
          colorBorder: '#E5E7EB',
          colorBorderSecondary: '#F0F1F5',
          colorBgLayout: '#F5F7FB',
          fontFamily:
            "-apple-system, 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', Roboto, sans-serif",
        },
        components: {
          Layout: { siderBg: '#FFFFFF', headerBg: '#FFFFFF' },
          Menu: { itemSelectedBg: '#EEF0FE', itemSelectedColor: '#4F46E5' },
          Card: { paddingLG: 24 },
        },
      }}
    >
      <HashRouter>
        <App />
      </HashRouter>
    </ConfigProvider>
  </React.StrictMode>,
);
