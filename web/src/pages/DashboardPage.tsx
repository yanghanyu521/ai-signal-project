import { useCallback, useEffect, useState } from 'react';
import { Alert, App as AntApp, Button, Col, Modal, Row } from 'antd';
import { ApiOutlined, CheckCircleOutlined, DatabaseOutlined, ReloadOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { getJson, postJson } from '../api/client';
import { DataTable, PageHeader, Section, StatCards } from '../components/common';
import BarChart from '../components/Chart';

export default function DashboardPage() {
  const [stats, setStats] = useState<any>(null);
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const { message } = AntApp.useApp();

  const load = useCallback(async () => {
    try {
      setError('');
      setStats(await getJson('/api/v1/statistics/overview'));
    } catch (exc: any) {
      setError(exc.message);
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
  if (!stats) return null;
  const totals = stats.totals || {};

  return (
    <>
      <PageHeader
        title="全局态势看板"
        description="事件库范围截至 2026-10-17；新增两家族的样本及报告尚未分析入库。主指标与实际处理进度分口径展示。"
        extra={<>
          <Button icon={<ReloadOutlined />} onClick={load}>刷新数据</Button>
          <Button type="primary" icon={<ApiOutlined />} onClick={() => navigate('/intake')}>开始联合分析</Button>
          <Button icon={<CheckCircleOutlined />} onClick={() => navigate('/baseline')}>基准评估</Button>
          <Button icon={<DatabaseOutlined />} onClick={importLegacy}>导入旧数据</Button>
        </>}
      />
      <Section title="事件库规模">
        <StatCards items={[
          { label: '全球 AI 安全事件', value: totals.global_ai_security_events },
          { label: '有样本、可分析事件', value: totals.analyzable_events },
          { label: '暂无样本事件', value: totals.events_without_samples },
          { label: '样本家族', value: totals.catalog_sample_families },
          { label: '已分析样本', value: totals.samples },
        ]} />
        <StatCards items={[
          { label: '去重报告', value: totals.catalog_logical_reports },
          { label: '家族—报告映射', value: totals.catalog_family_report_mappings },
        ]} />
        <Alert type="info" showIcon style={{ marginBottom: 0 }}
          message={`其中已分析入库 ${totals.sample_families} 个家族、${totals.samples} 个样本；已入库去重报告 ${totals.logical_reports} 份、家族—报告映射 ${totals.family_report_mappings} 组。CLOSEDQUORUM 与 CL-UNK-1211 的样本、报告仍待处理。`} />
      </Section>
      <Section title="研究与证据记录口径">
        <p>
          历史研究 CSV 收录 <b>{totals.curated_research_events}</b> 条事件；报告抽取产生 <b>{totals.report_event_records}</b> 条目标事件证据；
          报告表保留 <b>{totals.report_records}</b> 条原始记录，按标题逻辑去重后已入库 <b>{totals.logical_reports}</b> 份；
          当前共 <b>{totals.analysis_cases}</b> 个分析案例；交叉验证表保留 <b>{totals.cross_validation_records}</b> 条执行记录。
        </p>
        <TypographyText />
      </Section>
      <Row gutter={[20, 20]}>
        <Col xs={24} lg={12}>
          <Section title="历史研究事件发生月">
            {(stats.event_monthly || []).length
              ? <BarChart data={stats.event_monthly} xKey="month" yKey="count" xLabel="月份" yLabel="研究事件" />
              : '暂无日期完整的事件。'}
          </Section>
        </Col>
        <Col xs={24} lg={12}>
          <Section title="样本静态结论">
            {(stats.sample_classification || []).length
              ? <BarChart data={stats.sample_classification} xKey="label" yKey="count" xLabel="结论" yLabel="样本数" />
              : '暂无样本。'}
          </Section>
        </Col>
      </Row>
      <Section title="历史研究事件收录月趋势">
        {(stats.knowledge_monthly || []).length
          ? <BarChart data={stats.knowledge_monthly} xKey="month" yKey="count" xLabel="月份" yLabel="新收录研究事件" />
          : '暂无知识库收录记录。'}
      </Section>
      <Row gutter={[20, 20]}>
        <Col xs={24} lg={12}>
          <Section title="样本家族覆盖"><DataTable rows={stats.sample_family_distribution || []} /></Section>
        </Col>
        <Col xs={24} lg={12}>
          <Section title="具体模型分布"><DataTable rows={stats.model_distribution || []} /></Section>
        </Col>
      </Row>
      <p style={{ color: '#64748B', fontSize: 13 }}>
        统计口径：{stats.scope} · 截止 {stats.as_of}；数据库事件记录共 {totals.event_records} 条（证据/调研物理记录，不是全球事件数）。
      </p>
    </>
  );
}

function TypographyText() {
  return <p style={{ color: '#64748B', fontSize: 13, marginBottom: 0 }}>
    历史研究事件和已入库记录都不等于事件库中的 46 个全球 AI 安全事件；图表仍仅覆盖已入库数据。
  </p>;
}
