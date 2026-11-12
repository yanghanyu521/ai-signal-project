import { useCallback, useEffect, useState } from 'react';
import { Alert, App as AntApp, Button, Card, Col, Collapse, Modal, Row, Spin } from 'antd';
import { ApiOutlined, CheckCircleOutlined, DatabaseOutlined, ReloadOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { getJson, postJson } from '../api/client';
import { CompactStats, DataTable, PageHeader, Section, StatCards } from '../components/common';
import { BarChart, DonutChart, LineChart } from '../components/Chart';

export default function DashboardPage() {
  const [stats, setStats] = useState<any>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const { message } = AntApp.useApp();

  const load = useCallback(async () => {
    try {
      setError('');
      setStats(await getJson('/api/v1/statistics/overview'));
    } catch (exc: any) {
      setError(exc.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const importLegacy = () => {
    Modal.confirm({
      title: '导入旧项目数据',
      content: '将旧项目的安全结构化结果幂等导入知识库，不会重复新增。',
      okText: '确认导入',
      cancelText: '取消',
      onOk: async () => {
        const result = await postJson('/api/v1/knowledge/import-legacy', {
          include_samples: true, include_events: true, include_reports: true,
        });
        message.success(`导入完成：${JSON.stringify(result).slice(0, 120)}`);
        load();
      },
    });
  };

  if (error) return <Alert type="error" message={error} showIcon />;
  if (loading || !stats) return <Spin style={{ display: 'block', margin: '120px auto' }} />;
  const totals = stats.totals || {};

  return (
    <>
      <PageHeader
        title="全局态势看板"
        description="事件库范围截至 2026-10-17；主指标与实际处理进度分口径展示。"
        extra={<>
          <Button icon={<ReloadOutlined />} onClick={load}>刷新</Button>
          <Button icon={<CheckCircleOutlined />} onClick={() => navigate('/baseline')}>基准评估</Button>
          <Button icon={<DatabaseOutlined />} onClick={importLegacy}>导入旧数据</Button>
          <Button type="primary" icon={<ApiOutlined />} onClick={() => navigate('/intake')}>开始联合分析</Button>
        </>}
      />

      <StatCards variant="hero" items={[
        { label: '全球 AI 安全事件', value: totals.global_ai_security_events },
        { label: '有样本、可分析事件', value: totals.analyzable_events },
        { label: '已分析样本', value: totals.samples },
        { label: '去重报告', value: totals.catalog_logical_reports },
      ]} />
      <Card size="small" style={{ marginBottom: 24 }} styles={{ body: { padding: '14px 24px' } }}>
        <CompactStats items={[
          { label: '暂无样本事件', value: totals.events_without_samples },
          { label: '样本家族', value: totals.catalog_sample_families },
          { label: '家族—报告映射', value: totals.catalog_family_report_mappings },
          { label: '已入库家族', value: totals.sample_families },
          { label: '入库报告', value: totals.logical_reports },
        ]} />
      </Card>

      <Row gutter={[20, 20]}>
        <Col xs={24} lg={14}>
          <Section title="历史研究事件发生月">
            <BarChart data={stats.event_monthly || []} xKey="month" yKey="count" xLabel="月份" yLabel="研究事件" />
          </Section>
        </Col>
        <Col xs={24} lg={10}>
          <Section title="样本确认状态">
            <DonutChart data={stats.sample_classification || []} />
          </Section>
        </Col>
      </Row>
      <Section title="历史研究事件收录月趋势">
        <LineChart data={stats.knowledge_monthly || []} xKey="month" yKey="count" xLabel="月份" yLabel="新收录研究事件" />
      </Section>

      <Section title="研究与证据概览">
        <CompactStats items={[
          { label: '历史研究事件', value: totals.curated_research_events },
          { label: '报告证据记录', value: totals.report_event_records },
          { label: '原始报告记录', value: totals.report_records },
          { label: '分析案例', value: totals.analysis_cases },
          { label: '交叉验证记录', value: totals.cross_validation_records },
        ]} />
        <Collapse ghost style={{ marginTop: 8 }} items={[{
          key: 'notes', label: <span style={{ fontSize: 13, color: '#6B7280' }}>口径说明与待处理事项</span>,
          children: <div style={{ color: '#6B7280', fontSize: 13, lineHeight: 1.9 }}>
            <p>历史研究事件和已入库记录都不等于事件库中的 46 个全球 AI 安全事件；图表仅覆盖已入库数据。
              数据库事件记录共 {totals.event_records} 条，属于证据/调研物理记录，不是全球事件数。</p>
            <p style={{ marginBottom: 0 }}>其中已分析入库 {totals.sample_families} 个家族、{totals.samples} 个样本；
              已入库去重报告 {totals.logical_reports} 份、家族—报告映射 {totals.family_report_mappings} 组。
              CLOSEDQUORUM 与 CL-UNK-1211 的样本、报告仍待处理。</p>
          </div>,
        }]} />
      </Section>
      <Row gutter={[20, 20]}>
        <Col xs={24} lg={12}>
          <Section title="样本家族覆盖"><DataTable rows={stats.sample_family_distribution || []} /></Section>
        </Col>
        <Col xs={24} lg={12}>
          <Section title="具体模型分布"><DataTable rows={stats.model_distribution || []} /></Section>
        </Col>
      </Row>
      <p style={{ color: '#6B7280', fontSize: 13 }}>
        统计口径：{stats.scope} · 截止 {stats.as_of}
      </p>
    </>
  );
}
