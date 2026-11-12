import { useMemo, useState } from 'react';
import { Alert, Card, Col, Row, Segmented, Select, Tabs, Tag } from 'antd';
import { CheckCircleFilled, StopOutlined } from '@ant-design/icons';
import { DataTable, PageHeader, StatCards } from '../components/common';
import fruitshell from '../../../evaluation/script_baseline/fruitshell.json';
import lamehug from '../../../evaluation/script_baseline/lamehug.json';
import malterminal from '../../../evaluation/script_baseline/malterminal.json';
import phantomraven from '../../../evaluation/script_baseline/phantomraven.json';
import promptflux from '../../../evaluation/script_baseline/promptflux.json';
import quietvault from '../../../evaluation/script_baseline/quietvault.json';
import slopoly from '../../../evaluation/script_baseline/slopoly.json';
import reportSide from '../../../evaluation/script_baseline/report_side.json';
import metricsData from '../../../evaluation/script_baseline_metrics.json';

const families = [fruitshell, lamehug, malterminal, phantomraven, promptflux, quietvault, slopoly];
const samples = families.flatMap((family: any) =>
  family.samples.map((sample: any) => ({ ...sample, family: family.family, language: family.language })),
);

const SCOPE_LABELS: Record<string, string> = {
  script_with_ai_calls: '含 AI 调用',
  script_llm_assisted_no_ai_calls: 'LLM 辅助开发·无 AI 调用',
};
const CATEGORY_TAGS: Record<string, { color: string; label: string }> = {
  program_prompt: { color: 'blue', label: '程序提示词' },
  jailbreak_prompt: { color: 'red', label: '越狱提示词' },
  analyzer_injection: { color: 'purple', label: '分析器注入' },
  prompt_template_prefix: { color: 'default', label: '模板前缀' },
  image_generation_prompt: { color: 'orange', label: '图像提示词' },
  image_generation_negative_prompt: { color: 'orange', label: '图像负面提示词' },
  other: { color: 'default', label: '其他' },
};
const RELATION_COLORS: Record<string, string> = { supports: 'green', complements: 'blue', contradicts: 'red' };

function CallingTag({ value }: { value: unknown }) {
  if (value === true) return <Tag color="blue">AI 调用确认</Tag>;
  if (value === false) return <Tag color="green">无 AI 调用</Tag>;
  return <Tag color="orange">静态不可确认</Tag>;
}

function SampleCard({ sample }: { sample: any }) {
  const expectations = sample.extraction_expectations || {};
  return (
    <Card size="small" style={{ marginBottom: 16 }}
      title={<span style={{ fontWeight: 600 }}>{sample.family} <span style={{ color: '#94A3B8', fontWeight: 400, fontSize: 12 }}>{sample.sha256.slice(0, 24)}…</span></span>}
      extra={<><CallingTag value={sample.ai_calling} /><Tag>{sample.language}</Tag>{sample.obfuscation && <Tag color="orange">混淆</Tag>}</>}>
      {sample.same_as && <Alert type="info" showIcon style={{ marginBottom: 12 }}
        message={`近重复变体，基准继承自 ${sample.same_as.slice(0, 16)}…；差异：${sample.differences_from_reference}`} />}
      {sample.behavior_summary && <p>{sample.behavior_summary}</p>}
      {sample.network_indicators && <p style={{ color: '#64748B', fontSize: 13 }}>网络指标：{sample.network_indicators.join('；')}</p>}
      {(sample.toolchain || []).length > 0 && <>
        <h4>工具链</h4>
        <DataTable rows={sample.toolchain.map((tool: any) => ({
          模型: tool.model || '—',
          'SDK/调用': tool.sdk || tool.type || '—',
          '端点/CLI': tool.endpoint || (tool.clis ? tool.clis.map((cli: any) => `${cli.cmd} ${(cli.args || []).join(' ')}`).join('\n') : '—'),
          认证: tool.auth || '—',
        }))} />
      </>}
      {(sample.prompts || []).length > 0 && <>
        <h4 style={{ marginTop: 16 }}>提示词（{sample.prompts.length} 条）</h4>
        {sample.prompts.map((prompt: any, index: number) => {
          const tag = CATEGORY_TAGS[prompt.category] || CATEGORY_TAGS.other;
          const text = prompt.text || prompt.decoded_text || prompt.text_prefix;
          return (
            <div key={index} style={{ marginBottom: 12 }}>
              <Tag color={tag.color}>{tag.label}</Tag>
              <code style={{ color: '#64748B' }}>{prompt.id}</code>
              {text && <pre style={{ background: '#F6F8FB', borderRadius: 8, padding: 12, fontSize: 12, whiteSpace: 'pre-wrap', marginTop: 6 }}>{text}</pre>}
              {(prompt.key_elements || prompt.items || []).map((element: string, eIndex: number) => (
                <div key={eIndex} style={{ color: '#64748B', fontSize: 13 }}>· {element}</div>
              ))}
              {prompt.purpose && <div style={{ color: '#64748B', fontSize: 13 }}>用途：{prompt.purpose}</div>}
            </div>
          );
        })}
      </>}
      {(expectations.must_find || expectations.must_not_claim) && (
        <Row gutter={20} style={{ marginTop: 12 }}>
          <Col xs={24} md={12}>
            <h4><CheckCircleFilled style={{ color: '#15803D' }} /> 必须提取</h4>
            {(expectations.must_find || []).map((item: string, index: number) => (
              <div key={index} style={{ color: '#64748B', fontSize: 13 }}>· {item}</div>
            ))}
          </Col>
          <Col xs={24} md={12}>
            <h4><StopOutlined style={{ color: '#DC2626' }} /> 禁止输出（幻觉检查）</h4>
            {(expectations.must_not_claim || []).map((item: string, index: number) => (
              <div key={index} style={{ color: '#64748B', fontSize: 13 }}>· {item}</div>
            ))}
          </Col>
        </Row>
      )}
    </Card>
  );
}

function SamplesTab() {
  const [family, setFamily] = useState('全部');
  const [scope, setScope] = useState('全部');
  const visible = useMemo(() => samples.filter((sample) =>
    (family === '全部' || sample.family === family)
    && (scope === '全部' || sample.analysis_scope.startsWith(
      scope === '含 AI 调用' ? 'script_with_ai_calls' : 'script_llm_assisted')),
  ), [family, scope]);

  return (
    <>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 20 }}>
        <Select style={{ minWidth: 200 }} value={family} onChange={setFamily}
          options={['全部', ...new Set(samples.map((sample) => sample.family))].map((value) => ({ value, label: value }))} />
        <Segmented options={['全部', '含 AI 调用', 'LLM 辅助开发·无 AI 调用']} value={scope} onChange={(value) => setScope(value as string)} />
      </div>
      <StatCards items={[
        { label: '基准样本', value: samples.length },
        { label: '可确认 AI 调用', value: samples.filter((sample) => sample.ai_calling === true).length },
        { label: '当前筛选', value: visible.length },
      ]} />
      <DataTable rows={visible.map((sample) => ({
        家族: sample.family,
        'SHA-256 前12位': sample.sha256.slice(0, 12),
        语言: sample.language,
        范围: SCOPE_LABELS[sample.analysis_scope] || sample.analysis_scope,
        混淆: sample.obfuscation || '无',
        提示词数: (sample.prompts || []).length,
      }))} />
      <div style={{ marginTop: 20 }}>
        {visible.map((sample) => <SampleCard key={sample.sha256} sample={sample} />)}
      </div>
    </>
  );
}

function ReportsTab() {
  return (
    <>
      <Alert type="info" showIcon style={{ marginBottom: 16 }}
        message="报告侧特征与样本侧的预期交叉验证关系；组织/国家/时间字段只允许 complements。" />
      {reportSide.families.map((family: any) => (
        <Card key={family.family} size="small" title={family.family} style={{ marginBottom: 16 }}>
          {family.reports.map((report: any, index: number) => (
            <p key={index} style={{ fontSize: 13 }}>
              <b>{report.source}</b>
              <span style={{ color: '#64748B', display: 'block' }}>{JSON.stringify({ ...report, source: undefined })}</span>
            </p>
          ))}
          {family.cross_validation_expectations.map((relation: any, index: number) => (
            <div key={index} style={{ marginBottom: 8 }}>
              <Tag color={RELATION_COLORS[relation.relation] || 'default'}>{relation.relation}</Tag>
              <span>{relation.field}</span>
              {relation.note && <div style={{ color: '#64748B', fontSize: 13 }}>{relation.note}</div>}
            </div>
          ))}
          {family.note && <Alert type="info" message={family.note} showIcon />}
        </Card>
      ))}
    </>
  );
}

function MetricsTab() {
  const metrics: any = metricsData;
  const clean = metrics.scored > 0 && metrics.clean_samples === metrics.scored;
  return (
    <>
      {clean && <Alert type="success" icon={<CheckCircleFilled />} showIcon style={{ marginBottom: 16 }}
        message={`全部 ${metrics.scored} 个已评分样本通过基准检查，未发现幻觉或漏提。`} />}
      <StatCards items={[
        { label: '已评分样本', value: metrics.scored },
        { label: '无问题样本', value: metrics.clean_samples },
        { label: '未评分', value: metrics.missing_or_not_completed },
      ]} />
      <DataTable rows={(metrics.details || []).map((item: any) => ({
        家族: item.family,
        'SHA-256 前12位': item.sha256.slice(0, 12),
        状态: item.status,
        问题数: (item.findings || []).length,
        问题: (item.findings || []).map((finding: any) => finding.check).join('; '),
      }))} />
    </>
  );
}

export default function BaselinePage() {
  return (
    <>
      <PageHeader title="真实脚本基准与提取评估"
        description="19 个真实恶意脚本的人工分析基准：13 个可确认 AI 调用、2 个混淆不可静态确认、1 个分析器注入、3 个 LLM 辅助开发。基准只含特征与证据行号，不含恶意代码本体。" />
      <Tabs items={[
        { key: 'samples', label: '样本基准', children: <SamplesTab /> },
        { key: 'reports', label: '报告侧基准', children: <ReportsTab /> },
        { key: 'metrics', label: '评分结果', children: <MetricsTab /> },
      ]} />
    </>
  );
}
