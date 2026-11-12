import { Layout, Menu, Tag, Typography } from 'antd';
import {
  MonitorOutlined, ApiOutlined, NodeIndexOutlined, SwapOutlined, DatabaseOutlined,
  FileTextOutlined, CheckCircleOutlined,
} from '@ant-design/icons';
import { Link, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import DashboardPage from './pages/DashboardPage';
import IntakePage from './pages/IntakePage';
import AssociationsPage from './pages/AssociationsPage';
import CrossValidationPage from './pages/CrossValidationPage';
import KnowledgePage from './pages/KnowledgePage';
import BaselinePage from './pages/BaselinePage';
import ReportGenerationPage from './pages/ReportGenerationPage';

const { Sider, Content } = Layout;

const menuItems = [
  { key: 'group-overview', type: 'group' as const, label: '总览', children: [
    { key: '/', icon: <MonitorOutlined />, label: <Link to="/">全局看板</Link> },
  ] },
  { key: 'group-analysis', type: 'group' as const, label: '分析工作台', children: [
    { key: '/intake', icon: <ApiOutlined />, label: <Link to="/intake">联合分析</Link> },
    { key: '/associations', icon: <NodeIndexOutlined />, label: <Link to="/associations">样本关联</Link> },
    { key: '/cross-validation', icon: <SwapOutlined />, label: <Link to="/cross-validation">交叉验证</Link> },
  ] },
  { key: 'group-knowledge', type: 'group' as const, label: '知识与报告', children: [
    { key: '/knowledge', icon: <DatabaseOutlined />, label: <Link to="/knowledge">知识库</Link> },
    { key: '/report-generation', icon: <FileTextOutlined />, label: <Link to="/report-generation">生成报告</Link> },
  ] },
  { key: 'group-quality', type: 'group' as const, label: '质量评估', children: [
    { key: '/baseline', icon: <CheckCircleOutlined />, label: <Link to="/baseline">基准评估</Link> },
  ] },
];

export default function App() {
  const location = useLocation();
  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider width={292} theme="light" breakpoint="lg" collapsedWidth={72}
        style={{ borderRight: '1px solid #ECEEF5' }}>
        <div style={{ padding: '26px 22px 14px', display: 'flex', alignItems: 'center', gap: 14 }}>
          <img src="/logo.png" alt="logo" style={{ width: 56, height: 56, borderRadius: 14 }} />
          <div>
            <Typography.Text strong style={{ fontSize: 20, display: 'block' }}>AI 信号提取平台</Typography.Text>
            <Typography.Text type="secondary" style={{ fontSize: 13 }}>静态分析 · 报告提取</Typography.Text>
          </div>
        </div>
        <div style={{ padding: '0 22px 18px', display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <Tag color="geekblue" style={{ fontSize: 13, padding: '2px 8px' }}>v0.9</Tag>
          <Tag color="blue" style={{ fontSize: 13, padding: '2px 8px' }}>仅脚本样本</Tag>
          <Tag color="green" style={{ fontSize: 13, padding: '2px 8px' }}>纯静态·不外传</Tag>
        </div>
        <Menu mode="inline" items={menuItems} selectedKeys={[location.pathname]}
          style={{ borderInlineEnd: 'none', fontSize: 17 }} />
      </Sider>
      <Layout>
        <Content style={{ padding: '28px 32px', maxWidth: 1600, width: '100%', margin: '0 auto' }}>
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/intake" element={<IntakePage />} />
            <Route path="/associations" element={<AssociationsPage />} />
            <Route path="/cross-validation" element={<CrossValidationPage />} />
            <Route path="/knowledge" element={<KnowledgePage />} />
            <Route path="/baseline" element={<BaselinePage />} />
            <Route path="/report-generation" element={<ReportGenerationPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Content>
      </Layout>
    </Layout>
  );
}
