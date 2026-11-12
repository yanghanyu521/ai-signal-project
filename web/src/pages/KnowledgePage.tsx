import { useState } from 'react';
import { Alert, Button, Card, Collapse, Input } from 'antd';
import { SearchOutlined } from '@ant-design/icons';
import { getJson } from '../api/client';
import { DataTable, PageHeader, StatCards } from '../components/common';

const REASONS: Record<string, string> = {
  sample_match: '样本或家族关键词命中',
  event_name_match: '报告目标事件名称命中',
  report_match: '报告关键词命中后反查样本',
};
const RELATIONS: Record<string, string> = {
  analysis_case: '分析案例中的家族—报告关系',
  target_event_name: '报告内目标事件名称一致',
};

export default function KnowledgePage() {
  const [query, setQuery] = useState('');
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const search = async () => {
    if (!query.trim()) { setError('请输入关键词。'); return; }
    setLoading(true);
    setError('');
    try {
      setResult(await getJson('/api/v1/knowledge/search', { q: query.trim(), limit: 100 }));
    } catch (exc: any) {
      setError(exc.message);
    } finally {
      setLoading(false);
    }
  };

  const summary = result?.summary || {};
  const unlinked = result?.unlinked_direct_matches || {};

  return (
    <>
      <PageHeader title="本地知识库关联检索"
        description="输入样本名、家族、哈希、模型或报告关键词；结果会沿知识库关系找到匹配样本及其对应报告和目标事件。" />
      {error && <Alert type="error" message={error} showIcon style={{ marginBottom: 16 }} />}
      <div style={{ display: 'flex', gap: 12, marginBottom: 20, maxWidth: 720 }}>
        <Input size="large" placeholder="例如 FRUITSHELL、PROMPTFLUX、SHA-256、模型或报告标题"
          value={query} onChange={(event) => setQuery(event.target.value)} onPressEnter={search} />
        <Button type="primary" size="large" icon={<SearchOutlined />} loading={loading} onClick={search}>检索</Button>
      </div>
      {result && (
        <>
          <StatCards items={[
            { label: '匹配家族', value: summary.families || 0 },
            { label: '关联样本', value: summary.samples || 0 },
            { label: '对应报告', value: summary.reports || 0 },
            { label: '目标事件记录', value: summary.events || 0 },
          ]} />
          {(result.results || []).length === 0 && <Alert type="info" showIcon message="没有找到能够关联到样本的知识条目。" />}
          {(result.results || []).map((group: any, index: number) => {
            const subject = group.subject || {};
            return (
              <Card key={index} size="small" style={{ marginBottom: 16 }}
                title={subject.label || subject.family || '未标注样本'}>
                {(subject.match_reasons || []).length > 0 && (
                  <p style={{ color: '#64748B', fontSize: 13 }}>
                    检索命中依据：{subject.match_reasons.map((item: string) => REASONS[item] || item).join('、')}
                  </p>
                )}
                <h4>关联样本（{(group.samples || []).length}）</h4>
                <DataTable rows={(group.samples || []).map((item: any) => ({
                  'SHA-256': item.sha256,
                  文件名: item.original_name,
                  静态分析结论: item.llm_label,
                  模型厂商: item.model_vendor,
                  模型家族: item.model_family,
                  具体模型: item.model_name,
                  分析状态: item.status,
                }))} />
                <h4 style={{ marginTop: 16 }}>对应报告（{(group.reports || []).length}）</h4>
                {(group.reports || []).length === 0 && <Alert type="warning" message="该样本/家族尚未建立对应报告关系。" />}
                {(group.reports || []).map((report: any, rIndex: number) => (
                  <Card key={rIndex} type="inner" size="small" style={{ marginBottom: 12 }} title={report.title || '未命名报告'}>
                    <p style={{ color: '#64748B', fontSize: 13 }}>
                      发布方：{report.publisher || '未记录'}　发布日期：{report.publication_date || '未记录'}<br />
                      关联依据：{(report.relations || []).map((relation: any) =>
                        `${RELATIONS[relation.type] || '知识库关系'}${relation.case_title ? `（${relation.case_title}）` : ''}`
                      ).join('、') || '—'}
                    </p>
                    {(report.target_events || []).length ? (
                      <DataTable rows={report.target_events.map((item: any) => ({
                        目标事件: item.name,
                        事件类型: item.event_type,
                        发生时间: item.event_date,
                        '相关组织/地区': item.actor_region,
                        AI参与摘要: item.ai_summary,
                        模型或服务: item.model_service,
                      }))} />
                    ) : <span style={{ color: '#64748B', fontSize: 13 }}>该报告已与样本建立关系，但还没有匹配到同名目标事件记录。</span>}
                  </Card>
                ))}
              </Card>
            );
          })}
          {(unlinked.reports || unlinked.events) && (
            <Collapse style={{ marginTop: 16 }} items={[{
              key: 'unlinked', label: '未关联到样本的直接关键词命中',
              children: <>
                {unlinked.reports && <>
                  <h4>报告</h4>
                  <DataTable rows={unlinked.reports.map((item: any) => ({
                    报告标题: item.title, 发布方: item.publisher, 发布日期: item.publication_date, 状态: item.status,
                  }))} />
                </>}
                {unlinked.events && <>
                  <h4>事件</h4>
                  <DataTable rows={unlinked.events.map((item: any) => ({
                    事件名称: item.name, 事件类型: item.event_type, 发生时间: item.event_date,
                    '相关组织/地区': item.actor_region, AI参与摘要: item.ai_summary, 模型或服务: item.model_service,
                  }))} />
                </>}
              </>,
            }]} />
          )}
          <p style={{ color: '#64748B' }}>{result.interpretation}</p>
        </>
      )}
    </>
  );
}
