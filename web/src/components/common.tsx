import { Card, Col, Row, Statistic, Table, Typography } from 'antd';
import type { ReactNode } from 'react';

export function PageHeader({ title, description, extra }: { title: string; description?: string; extra?: ReactNode }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24, gap: 16, flexWrap: 'wrap' }}>
      <div style={{ minWidth: 0 }}>
        <Typography.Title level={2} style={{ margin: 0, fontSize: 26, fontWeight: 650 }}>{title}</Typography.Title>
        {description && (
          <Typography.Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0, maxWidth: 860, fontSize: 14 }}>
            {description}
          </Typography.Paragraph>
        )}
      </div>
      {extra && <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>{extra}</div>}
    </div>
  );
}

type StatItem = { label: string; value: string | number | null | undefined };

export function StatCards({ items, variant = 'default' }: { items: StatItem[]; variant?: 'default' | 'hero' }) {
  return (
    <Row gutter={[16, 16]} style={{ marginBottom: 20 }}>
      {items.map((item) => (
        <Col key={item.label} flex="1 1 170px">
          <Card size="small" styles={{ body: { padding: variant === 'hero' ? '20px 24px' : '14px 20px' } }}>
            <Statistic
              title={<span style={{ fontSize: 13 }}>{item.label}</span>}
              value={item.value ?? '—'}
              valueStyle={{ fontSize: variant === 'hero' ? 34 : 26, fontWeight: 650 }}
            />
          </Card>
        </Col>
      ))}
    </Row>
  );
}

export function CompactStats({ items }: { items: StatItem[] }) {
  return (
    <Row gutter={[16, 12]} style={{ marginBottom: 4 }}>
      {items.map((item) => (
        <Col key={item.label}>
          <span style={{ color: '#6B7280', fontSize: 13 }}>{item.label}</span>
          <span style={{ marginLeft: 10, fontSize: 20, fontWeight: 600 }}>{item.value ?? '—'}</span>
        </Col>
      ))}
    </Row>
  );
}

export function DataTable({ rows, rowKey, maxHeight }: { rows: Record<string, unknown>[]; rowKey?: string; maxHeight?: number }) {
  if (!rows.length) return <Typography.Text type="secondary">暂无数据</Typography.Text>;
  const columns = Object.keys(rows[0]).map((key) => ({
    title: key,
    dataIndex: key,
    key,
    ellipsis: true,
    render: (value: unknown) => {
      if (value === null || value === undefined || value === '') return '—';
      if (typeof value === 'boolean') return value ? '是' : '否';
      if (typeof value === 'object') return JSON.stringify(value);
      return String(value);
    },
  }));
  return (
    <Table
      size="middle"
      columns={columns}
      dataSource={rows.map((row, index) => ({ ...row, __key: rowKey ? String(row[rowKey]) : index }))}
      rowKey="__key"
      pagination={rows.length > 12 ? { pageSize: 12, hideOnSinglePage: true } : false}
      scroll={{ x: 'max-content', y: maxHeight }}
    />
  );
}

export function Section({ title, children, extra }: { title: string; children: ReactNode; extra?: ReactNode }) {
  return (
    <Card title={title} size="small" style={{ marginBottom: 20 }} styles={{ header: { fontWeight: 600 } }} extra={extra}>
      {children}
    </Card>
  );
}
