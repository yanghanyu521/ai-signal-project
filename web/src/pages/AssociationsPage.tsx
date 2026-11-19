import { useEffect, useState } from 'react';
import { Alert, App as AntApp, Button, Card, Col, Row, Segmented, Select, Switch } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { getJson, postJson } from '../api/client';
import { DataTable, PageHeader, Section, StatCards } from '../components/common';

const percent = (value: unknown) => (typeof value === 'number' ? `${(value * 100).toFixed(1)}%` : '—');
const REASONS: Record<string, string> = {
  missing_toolchain_evidence: '缺少工具链证据', missing_prompt_evidence: '缺少Prompt证据',
  missing_comparable_prompt_evidence: '没有共同可比较的Prompt证据类型', different_languages: '语言不同',
  invalid_source_quality: '源码质量不满足比较条件', not_original_source: '非原始源码（仅字符串/恢复代码）',
  parse_error: '源码解析失败', unknown_language: '语言未知', missing_metrics: '缺少统计指标',
  python_ast_unavailable: '缺少Python AST指标', insufficient_metrics: '有效统计指标不足',
  insufficient_shared_metrics: '共同有效统计指标不足',
};
const reason = (value: string | undefined) => (value ? REASONS[value] || value : '');

export default function AssociationsPage() {
  const [samples, setSamples] = useState<any[]>([]);
  const [selected, setSelected] = useState<string>();
  const [view, setView] = useState<string>('综合 AI 信号');
  const [includeUnmatched, setIncludeUnmatched] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');
  const { message } = AntApp.useApp();

  useEffect(() => {
    getJson<any[]>('/api/v1/samples', { limit: 500 })
      .then((items) => { setSamples(items); if (items.length) setSelected(items[0].sha256); })
      .catch((exc) => setError(exc.message));
  }, []);

  const load = async (sha = selected, currentView = view, unmatched = includeUnmatched) => {
    if (!sha) return;
    try {
      setError('');
      const path = currentView === '代码文体' ? 'style-neighbors' : 'associations';
      setResult(await getJson(`/api/v1/samples/${sha}/${path}`, { limit: 100, include_unmatched: unmatched }));
    } catch (exc: any) {
      setError(exc.message);
    }
  };

  useEffect(() => { load(); }, [selected, view, includeUnmatched]);

  const recluster = async () => {
    try {
      const rebuilt = await postJson<any>('/api/v1/samples/recluster', {});
      message.success(`已完成 ${rebuilt.sample_count} 个样本、${rebuilt.cluster_count} 个簇的重建。`);
      load();
    } catch (exc: any) {
      setError(exc.message);
    }
  };

  const related = result?.related_samples || [];
  const rows = related.map((item: any) => view === '代码文体' ? {
    样本SHA256: item.related_sha256,
    家族: item.source_case,
    文体相似度: percent(item.code_style_similarity),
    状态: item.comparison?.status,
    原因: reason(item.comparison?.reason) || '—',
    近重复: item.comparison?.near_duplicate_warning ? '是' : '否',
  } : {
    样本SHA256: item.related_sha256,
    家族: item.source_case,
    总关联分: percent(item.overall_similarity),
    工具链事实: percent(item.toolchain_similarity),
    Prompt内容结构: percent(item.prompt_similarity),
    代码统计: percent(item.code_style_similarity),
    可比权重覆盖率: percent(item.comparable_weight),
    同一聚类: item.same_cluster ? '是' : '否',
    代码统计可比性: reason(item.comparison?.groups?.code_style?.reason)
      || (item.comparison?.groups?.code_style?.status === 'comparable' ? '可比较' : '旧结果待重建'),
  });

  return (
    <>
      <PageHeader title="样本聚类与关联分析"
        description="工具链事实、Prompt哈希/结构、合格源码统计分别评分后加权合成，再做层次聚类；分数不是同源或AI生成概率。"
        extra={<Button icon={<ReloadOutlined />} onClick={recluster}>重建全部聚类</Button>} />
      {error && <Alert type="error" message={error} showIcon style={{ marginBottom: 16 }} />}
      <Card size="small" style={{ marginBottom: 20 }}>
        <Row gutter={[20, 16]} align="middle">
          <Col flex="auto">
            <Select style={{ width: '100%' }} value={selected} onChange={setSelected} showSearch optionFilterProp="label"
              options={samples.map((item) => ({
                value: item.sha256,
                label: `${item.source_case || '未标注'} · ${item.model_name || 'unknown'} · ${item.sha256.slice(0, 12)}…`,
              }))} />
          </Col>
          <Col><Segmented options={['综合 AI 信号', '代码文体']} value={view} onChange={(value) => setView(value as string)} /></Col>
          <Col>
            <Switch checked={includeUnmatched} onChange={setIncludeUnmatched} />
            <span style={{ marginLeft: 8, color: '#64748B' }}>显示零匹配及不可比较的样本对</span>
          </Col>
        </Row>
      </Card>
      {result && view !== '代码文体' && (
        <StatCards items={[
          { label: '聚类编号', value: result.cluster?.cluster_label || '未聚类' },
          { label: '簇内样本', value: result.cluster?.cluster_size || 0 },
          { label: '返回近邻', value: related.length },
        ]} />
      )}
      {result?.message && <Alert type="info" message={result.message} showIcon style={{ marginBottom: 16 }} />}
      <Section title={view === '代码文体' ? '代码文体近邻' : '关联样本'}>
        {rows.length ? <DataTable rows={rows} /> : '当前筛选下没有结果；可开启上方选项查看零分及不可比较原因。'}
        {result?.run && <p style={{ color: '#64748B', fontSize: 13 }}>
          算法：{result.run.algorithm_version}；聚类距离阈值：{result.run.distance_threshold}。阈值只决定同簇关系，不屏蔽有正分的跨簇候选。
        </p>}
        {view !== '代码文体' && <p style={{ color: '#64748B', fontSize: 13 }}>
          分数空白表示不可比较，不等于0%；0%表示有可比证据但无匹配。总分不把缺失组权重分摊到其他组。
        </p>}
      </Section>
      {result?.interpretation && <p style={{ color: '#64748B' }}>{result.interpretation}</p>}
    </>
  );
}
