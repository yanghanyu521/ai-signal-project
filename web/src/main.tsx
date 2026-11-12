import React from 'react';
import ReactDOM from 'react-dom/client';
import { HashRouter } from 'react-router-dom';
import { ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import App from './App';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider
      locale={zhCN}
      theme={{
        token: {
          colorPrimary: '#4F46E5',
          colorInfo: '#4F46E5',
          borderRadius: 10,
          fontSize: 14,
          colorText: '#1E293B',
          colorBgLayout: '#F5F6FA',
          fontFamily:
            "-apple-system, 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', Roboto, sans-serif",
        },
        components: {
          Layout: { siderBg: '#FFFFFF', headerBg: '#FFFFFF' },
          Menu: { itemSelectedBg: '#EEF0FE', itemSelectedColor: '#4F46E5' },
        },
      }}
    >
      <HashRouter>
        <App />
      </HashRouter>
    </ConfigProvider>
  </React.StrictMode>,
);
