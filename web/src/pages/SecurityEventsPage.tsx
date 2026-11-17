import { useCallback, useEffect, useState } from 'react';
import {
  Alert, App as AntApp, Button, Card, Col, DatePicker, Descriptions, Drawer,
  Form, Input, Modal, Popconfirm, Row, Select, Space, Table, Tag, Typography, Upload,
} from 'antd';
import { CopyOutlined, DeleteOutlined, PlusOutlined, ReloadOutlined, UploadOutlined } from '@ant-design/icons';
import dayjs from 'dayjs';
import { deleteJson, getJson, postFiles, postJson, putJson } from '../api/client';
import { PageHeader } from '../components/common';

const EVENT_TYPES = ['AI辅助恶意样本开发', '恶意行为调用AI', 'Agent编排攻击行动'];
const TYPE_COLORS: Record<string, string> = {
  AI辅助恶意样本开发: 'purple',
  恶意行为调用AI: 'blue',
  Agent编排攻击行动: 'geekblue',
};

function noteOf(entry: any): string {
  if (entry?.note) return entry.note;
  let text = String(entry?.text || '');
  (entry?.hashes || []).forEach((hash: string) => { text = text.split(hash).join(''); });
  return text.replace(/^(SHA-?256|SHA-?1|MD5):/i, '').replace(/^[（(]\s*/, '').replace(/\s*[）)]$/, '').trim();
}

const HASH_TYPE_OPTIONS = ['SHA-256', 'SHA-1', 'MD5', '其他'];
function hashTypeOf(hash: string): string {
  if (/^[a-fA-F0-9]{64}$/.test(hash)) return 'SHA-256';
  if (/^[a-fA-F0-9]{40}$/.test(hash)) return 'SHA-1';
  if (/^[a-fA-F0-9]{32}$/.test(hash)) return 'MD5';
  return '其他';
}

type EventFormValues = {
  event_id?: string;
  name: string;
  event_date?: any;
  event_types: string[];
  summary?: string;
  samples?: { hash_type?: string; hash?: string; note?: string }[];
  source?: string;
  status?: string;
};

function EventFormModal({ open, initial, onClose, onSaved }: {
  open: boolean;
  initial: any | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [form] = Form.useForm<EventFormValues>();
  const [saving, setSaving] = useState(false);
  const { message } = AntApp.useApp();

  useEffect(() => {
    if (!open) return;
    form.setFieldsValue({
      event_id: initial?.event_id,
      name: initial?.name || '',
      event_date: initial?.event_date ? dayjs(initial.event_date) : null,
      event_types: initial?.event_types || [],
      summary: initial?.summary || '',
      samples: (initial?.samples?.entries || [])
        .map((entry: any) => ({ hash_type: entry.hash_type || hashTypeOf(entry.hashes?.[0] || ''), hash: entry.hashes?.[0] || '', note: noteOf(entry) }))
        .filter((row: any) => row.hash || (row.note && row.note !== '无')),
      source: initial?.source || '',
      status: initial?.status || '新增',
    });
  }, [open, initial, form]);

  const save = async () => {
    const values = await form.validateFields();
    const payload = {
      name: values.name,
      event_date: values.event_date ? values.event_date.format('YYYY-MM-DD') : null,
      event_types: values.event_types || [],
      summary: values.summary,
      sample_entries: (values.samples || [])
        .map((row) => ({ hash_type: row?.hash_type || 'SHA-256', hash: (row?.hash || '').trim(), note: (row?.note || '').trim() }))
        .filter((row) => row.hash || row.note),
      source: values.source,
      status: values.status,
    };
    setSaving(true);
    try {
      if (initial?.event_id) {
        await putJson(`/api/v1/security-events/${initial.event_id}`, payload);
        message.success('事件已更新');
      } else {
        await postJson('/api/v1/security-events', { ...payload, event_id: values.event_id || undefined });
        message.success('事件已创建');
      }
      onSaved();
      onClose();
    } catch (exc: any) {
      message.error(exc.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      title={initial ? '编辑事件' : '新增事件'}
      open={open}
      onCancel={onClose}
      onOk={save}
      confirmLoading={saving}
      okText="保存"
      cancelText="取消"
      width={720}
      styles={{ body: { maxHeight: '62vh', overflowY: 'auto' } }}
      destroyOnHidden
    >
      <Form form={form} layout="vertical">
        {!initial && (
          <Form.Item name="event_id" label="事件 ID（可选，留空自动生成）">
            <Input placeholder="例如 AISEC-20260101-XXX-NAME" />
          </Form.Item>
        )}
        <Form.Item name="name" label="事件名称" rules={[{ required: true, whitespace: true, message: '事件名称不能为空' }]}>
          <Input placeholder="例如 APT28/LAMEHUG 调用 Qwen 生成窃密命令" />
        </Form.Item>
        <Row gutter={16}>
          <Col span={12}>
            <Form.Item name="event_date" label="报告时间（首次披露日期）">
              <DatePicker style={{ width: '100%' }} />
            </Form.Item>
          </Col>
          <Col span={12}>
            <Form.Item name="status" label="状态">
              <Select options={['新增', '更新', '已复核', '排除'].map((value) => ({ value, label: value }))} />
            </Form.Item>
          </Col>
        </Row>
        <Form.Item name="event_types" label="事件类型" rules={[{ required: true, message: '至少选择一种事件类型' }]}>
          <Select mode="multiple" options={EVENT_TYPES.map((value) => ({ value, label: value }))} />
        </Form.Item>
        <Form.Item name="summary" label="事件概要">
          <Input.TextArea rows={4} />
        </Form.Item>
        <Form.Item label="可分析样本哈希" extra="一行一个样本：类型、哈希值、注释分别填写；点下方按钮添加更多行。">
          <Form.List name="samples">
            {(fields, { add, remove }) => (
              <>
                {fields.map((field) => (
                  <div key={field.key} style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                    <Form.Item name={[field.name, 'hash_type']} noStyle initialValue="SHA-256">
                      <Select style={{ width: 110 }} options={HASH_TYPE_OPTIONS.map((value) => ({ value, label: value }))} />
                    </Form.Item>
                    <Form.Item name={[field.name, 'hash']} noStyle
                      rules={[{ validator: (_rule, value) => {
                        if (!value) return Promise.resolve();
                        const row = form.getFieldValue(['samples', field.name]) || {};
                        const lengths: Record<string, number> = { 'SHA-256': 64, 'SHA-1': 40, MD5: 32 };
                        const expected = lengths[row.hash_type];
                        if (expected && !new RegExp(`^[a-fA-F0-9]{${expected}}$`).test(value)) {
                          return Promise.reject(new Error(`${row.hash_type} 需 ${expected} 位十六进制`));
                        }
                        return Promise.resolve();
                      } }]}>
                      <Input placeholder="哈希值" style={{ fontFamily: 'monospace' }} />
                    </Form.Item>
                    <Form.Item name={[field.name, 'note']} noStyle>
                      <Input placeholder="注释（可选）" style={{ width: 200 }} />
                    </Form.Item>
                    <Button type="text" danger icon={<DeleteOutlined />} onClick={() => remove(field.name)} />
                  </div>
                ))}
                <Button type="dashed" block icon={<PlusOutlined />} onClick={() => add({ hash_type: 'SHA-256' })}>添加样本哈希行</Button>
              </>
            )}
          </Form.List>
        </Form.Item>
        <Form.Item name="source" label="来源（多个链接用分号或换行分隔）">
          <Input.TextArea rows={2} />
        </Form.Item>
      </Form>
    </Modal>
  );
}

function EventDetailDrawer({ eventId, onClose, onEdit }: {
  eventId: string | null;
  onClose: () => void;
  onEdit: (detail: any) => void;
}) {
  const [detail, setDetail] = useState<any>(null);
  const [error, setError] = useState('');
  const { message } = AntApp.useApp();

  useEffect(() => {
    if (!eventId) { setDetail(null); return; }
    getJson<any>(`/api/v1/security-events/${eventId}`).then(setDetail).catch((exc) => setError(exc.message));
  }, [eventId]);

  return (
    <Drawer title="事件详情" width={640} open={!!eventId} onClose={onClose}
      extra={detail && <Button type="primary" ghost onClick={() => onEdit(detail)}>编辑</Button>}>
      {error && <Alert type="error" message={error} showIcon />}
      {detail && (
        <>
          <Typography.Title level={5} style={{ marginTop: 0 }}>{detail.name}</Typography.Title>
          <div style={{ marginBottom: 16 }}>
            {(detail.event_types || []).map((type: string) => <Tag key={type} color={TYPE_COLORS[type]}>{type}</Tag>)}
            <Tag>{detail.status || '—'}</Tag>
            {detail.has_samples ? <Tag color="green">有可分析样本</Tag> : <Tag>无可分析样本</Tag>}
          </div>
          <Descriptions column={1} size="small" bordered items={[
            { key: 'id', label: '事件 ID', children: detail.event_id },
            { key: 'date', label: '报告时间', children: detail.event_date || '—' },
            { key: 'seen', label: '首次入库时间', children: detail.first_seen_at || '—' },
            { key: 'updated', label: '最近更新时间', children: detail.updated_at || '—' },
          ]} />
          <Typography.Title level={5} style={{ marginTop: 24 }}>事件概要</Typography.Title>
          <Typography.Paragraph style={{ lineHeight: 1.9 }}>{detail.summary || '—'}</Typography.Paragraph>
          <Typography.Title level={5}>可分析样本哈希（{detail.samples?.sample_count || 0}）</Typography.Title>
          {(detail.samples?.entries || []).length === 0 && <Typography.Text type="secondary">无</Typography.Text>}
          {(detail.samples?.entries || []).map((entry: any, index: number) => {
            if (!(entry.hashes || []).length) {
              return <div key={index}><Typography.Text type="secondary">{entry.text}</Typography.Text></div>;
            }
            return (entry.hashes || []).map((hash: string) => (
              <div key={hash} style={{ marginBottom: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Tag style={{ margin: 0 }}>{entry.hash_type || hashTypeOf(hash)}</Tag>
                  <code style={{ background: '#F6F8FB', padding: '6px 10px', borderRadius: 6, fontSize: 12, flex: 1, wordBreak: 'break-all' }}>{hash}</code>
                  <Button size="small" icon={<CopyOutlined />} onClick={async () => {
                    await navigator.clipboard.writeText(hash);
                    message.success('哈希已复制');
                  }}>复制</Button>
                </div>
                {noteOf(entry) && <Typography.Text type="secondary" style={{ fontSize: 13 }}>{noteOf(entry)}</Typography.Text>}
              </div>
            ));
          })}
          <Typography.Title level={5}>来源</Typography.Title>
          {(detail.sources || []).length === 0 && <Typography.Text type="secondary">—</Typography.Text>}
          <ul style={{ paddingLeft: 18, lineHeight: 2 }}>
            {(detail.sources || []).map((source: string, index: number) => (
              <li key={index} style={{ wordBreak: 'break-all', fontSize: 13 }}>
                {source.startsWith('http')
                  ? <Typography.Link href={source} target="_blank" rel="noreferrer">{source}</Typography.Link>
                  : source}
              </li>
            ))}
          </ul>
        </>
      )}
    </Drawer>
  );
}

export default function SecurityEventsPage() {
  const [filters, setFilters] = useState<any>({});
  const [reportRange, setReportRange] = useState<any>([null, null]);
  const [seenRange, setSeenRange] = useState<any>([null, null]);
  const [eventType, setEventType] = useState<string>();
  const [hasSamples, setHasSamples] = useState<string>();
  const [keyword, setKeyword] = useState('');
  const [data, setData] = useState<{ total: number; items: any[] }>({ total: 0, items: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(15);
  const [detailId, setDetailId] = useState<string | null>(null);
  const [editor, setEditor] = useState<{ open: boolean; initial: any | null }>({ open: false, initial: null });
  const { message } = AntApp.useApp();

  const load = useCallback(async (pageNo = page, size = pageSize) => {
    setLoading(true);
    try {
      setError('');
      setData(await getJson('/api/v1/security-events', {
        report_date_from: reportRange?.[0]?.format('YYYY-MM-DD'),
        report_date_to: reportRange?.[1]?.format('YYYY-MM-DD'),
        first_seen_from: seenRange?.[0]?.format('YYYY-MM-DD'),
        first_seen_to: seenRange?.[1]?.format('YYYY-MM-DD'),
        event_type: eventType,
        has_samples: hasSamples === undefined ? undefined : hasSamples === '有',
        q: keyword || undefined,
        limit: size,
        offset: (pageNo - 1) * size,
      }));
    } catch (exc: any) {
      setError(exc.message);
    } finally {
      setLoading(false);
    }
  }, [reportRange, seenRange, eventType, hasSamples, keyword, page, pageSize]);

  useEffect(() => { load(1, pageSize); }, [filters]);

  const reset = () => {
    setReportRange([null, null]);
    setSeenRange([null, null]);
    setEventType(undefined);
    setHasSamples(undefined);
    setKeyword('');
    setFilters({});
    setPage(1);
  };

  const remove = async (eventId: string) => {
    try {
      await deleteJson(`/api/v1/security-events/${eventId}`);
      message.success('事件已删除');
      load();
    } catch (exc: any) {
      message.error(exc.message);
    }
  };

  const [importOpen, setImportOpen] = useState(false);
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importing, setImporting] = useState(false);

  const importUpload = async () => {
    if (!importFile) { message.warning('请先选择要导入的表格文件'); return; }
    setImporting(true);
    try {
      const result = await postFiles<any>('/api/v1/security-events/import', { file: importFile }, {});
      message.success(`已导入/更新 ${result.imported} 条事件`);
      setImportOpen(false);
      setImportFile(null);
      load();
    } catch (exc: any) {
      message.error(exc.message);
    } finally {
      setImporting(false);
    }
  };

  return (
    <>
      <PageHeader title="AI 安全事件库"
        description="目前搜集到的全球 AI 安全事件。支持按报告时间、事件类型、样本可用性与入库时间筛选；点击事件名称查看完整详情。"
        extra={<>
          <Button icon={<UploadOutlined />} onClick={() => setImportOpen(true)}>导入事件</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setEditor({ open: true, initial: null })}>新增事件</Button>
        </>} />
      {error && <Alert type="error" message={error} showIcon style={{ marginBottom: 16 }} />}
      <Card size="small" style={{ marginBottom: 20 }}>
        <Row gutter={[16, 16]}>
          <Col xs={24} sm={12} lg={6}>
            <div style={{ marginBottom: 6, color: '#6B7280', fontSize: 13 }}>报告时间</div>
            <DatePicker.RangePicker style={{ width: '100%' }} value={reportRange}
              onChange={(values) => setReportRange(values || [null, null])} />
          </Col>
          <Col xs={24} sm={12} lg={5}>
            <div style={{ marginBottom: 6, color: '#6B7280', fontSize: 13 }}>事件类型</div>
            <Select allowClear style={{ width: '100%' }} placeholder="全部" value={eventType}
              onChange={setEventType} options={EVENT_TYPES.map((value) => ({ value, label: value }))} />
          </Col>
          <Col xs={24} sm={12} lg={4}>
            <div style={{ marginBottom: 6, color: '#6B7280', fontSize: 13 }}>可分析样本</div>
            <Select allowClear style={{ width: '100%' }} placeholder="全部" value={hasSamples}
              onChange={setHasSamples} options={['有', '无'].map((value) => ({ value, label: value }))} />
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <div style={{ marginBottom: 6, color: '#6B7280', fontSize: 13 }}>入库时间</div>
            <DatePicker.RangePicker style={{ width: '100%' }} value={seenRange}
              onChange={(values) => setSeenRange(values || [null, null])} />
          </Col>
          <Col xs={24} sm={12} lg={3}>
            <div style={{ marginBottom: 6, color: '#6B7280', fontSize: 13 }}>关键词</div>
            <Input placeholder="名称 / ID / 概要" value={keyword} onChange={(event) => setKeyword(event.target.value)}
              onPressEnter={() => { setPage(1); setFilters({ ...filters }); }} />
          </Col>
        </Row>
        <div style={{ marginTop: 16, display: 'flex', gap: 10 }}>
          <Button type="primary" onClick={() => { setPage(1); setFilters({ ...filters }); }}>查询</Button>
          <Button onClick={reset}>重置</Button>
          <Button icon={<ReloadOutlined />} onClick={() => load()}>刷新</Button>
        </div>
      </Card>
      <Card size="small">
        <Table
          rowKey="event_id"
          loading={loading}
          dataSource={data.items}
          scroll={{ x: 1100 }}
          tableLayout="fixed"
          pagination={{
            current: page,
            pageSize,
            total: data.total,
            showSizeChanger: true,
            showTotal: (total) => `共 ${total} 条事件`,
            onChange: (pageNo, size) => { setPage(pageNo); setPageSize(size); load(pageNo, size); },
          }}
          columns={[
            { title: '时间', dataIndex: 'event_date', width: 110 },
            {
              title: '事件名称', dataIndex: 'name', ellipsis: true,
              render: (value: string, record: any) => (
                <Typography.Link onClick={() => setDetailId(record.event_id)}>{value}</Typography.Link>
              ),
            },
            {
              title: '事件类型', dataIndex: 'event_types', width: 300,
              render: (types: string[]) => <>{(types || []).map((type) => <Tag key={type} color={TYPE_COLORS[type]} style={{ marginBottom: 4 }}>{type}</Tag>)}</>,
            },
            {
              title: '可分析样本', dataIndex: 'has_samples', width: 130,
              render: (_: unknown, record: any) => record.has_samples
                ? <Tag color="green">有 · {record.sample_count} 个</Tag>
                : <Tag>无</Tag>,
            },
            { title: '入库时间', dataIndex: 'first_seen_at', width: 120, render: (value: string) => (value || '').slice(0, 10) || '—' },
            { title: '状态', dataIndex: 'status', width: 80 },
            {
              title: '操作', key: 'actions', width: 190,
              render: (_: unknown, record: any) => (
                <Space size={4}>
                  <Button type="link" size="small" onClick={() => setDetailId(record.event_id)}>详情</Button>
                  <Button type="link" size="small" onClick={async () => {
                    const detail = await getJson<any>(`/api/v1/security-events/${record.event_id}`);
                    setEditor({ open: true, initial: detail });
                  }}>编辑</Button>
                  <Popconfirm title="确定删除该事件？此操作不可恢复" okText="删除" okButtonProps={{ danger: true }}
                    cancelText="取消" onConfirm={() => remove(record.event_id)}>
                    <Button type="link" size="small" danger>删除</Button>
                  </Popconfirm>
                </Space>
              ),
            },
          ]}
        />
      </Card>
      <EventDetailDrawer eventId={detailId} onClose={() => setDetailId(null)}
        onEdit={(detail) => { setDetailId(null); setEditor({ open: true, initial: detail }); }} />
      <EventFormModal open={editor.open} initial={editor.initial}
        onClose={() => setEditor({ open: false, initial: null })} onSaved={() => load()} />
      <Modal title="导入事件" open={importOpen} onCancel={() => setImportOpen(false)}
        onOk={importUpload} confirmLoading={importing} okText="开始导入" cancelText="取消">
        <p style={{ color: '#6B7280', fontSize: 13 }}>上传与 AI安全事件库.xlsx 同格式的表格（需含“事件库”工作表）。按事件 ID 幂等导入/更新，不会删除手工新增的事件。</p>
        <Upload.Dragger accept=".xlsx,.xls" maxCount={1}
          beforeUpload={(file) => { setImportFile(file); return false; }}
          onRemove={() => setImportFile(null)}>
          <p className="ant-upload-text">点击或拖拽表格文件到此</p>
          <p className="ant-upload-hint">支持 .xlsx / .xls</p>
        </Upload.Dragger>
      </Modal>
    </>
  );
}
