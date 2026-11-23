import { useState } from 'react'
import { Alert, Button, Card, DatePicker, Form, Input, InputNumber, Modal, Select, Space, Table, Tag, Typography, message } from 'antd'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { agentEndpointApi, agentKeys } from '../../services/agentEndpoint'
import type { EnrollmentCreated, EnrollmentToken } from '../../services/agentEndpoint.types'
import { secretVisible } from './testable'
import { label, modes, products, time } from './dict'


export default function AgentEnrollment() {
  const [page,setPage]=useState(1)
  const [showCreate,setShowCreate]=useState(false)
  const [created,setCreated]=useState<EnrollmentCreated|null>(null)
  const [form]=Form.useForm()
  const qc=useQueryClient()
  const listing=useQuery({queryKey:agentKeys.enrollment(page),queryFn:()=>agentEndpointApi.enrollment(page)})
  const create=useMutation({mutationFn:agentEndpointApi.createEnrollment,onSuccess:value=>{setShowCreate(false);form.resetFields();setCreated(value);void qc.invalidateQueries({queryKey:[...agentKeys.scope,'enrollment']})},onError:()=>message.error('注册令牌创建失败')})
  const revoke=useMutation({mutationFn:agentEndpointApi.revokeEnrollment,onSuccess:()=>{void qc.invalidateQueries({queryKey:[...agentKeys.scope,'enrollment']});message.success('已吊销')},onError:()=>message.error('吊销失败')})
  const url=(import.meta.env.VITE_AGENT_GATEWAY_URL || (import.meta.env.DEV ? "http://" + window.location.hostname + ":28080" : "<网关地址>"))
  const command=created?`hookd enroll --server ${url} --token ${created.token}`:''
  const probe=created?`aiprobe enroll --server ${url} --token ${created.token}`:''
  return <div style={{display:'grid',gap:16}}><Space style={{justifyContent:'space-between'}}><Typography.Title level={3}>注册令牌</Typography.Title><Button type="primary" onClick={()=>setShowCreate(true)}>创建注册令牌</Button></Space>
    <Alert type="info" showIcon message="注册令牌明文仅创建后显示一次；后续列表仅展示前缀，请立即复制并妥善保存。" />
    <Card><Table rowKey="id" loading={listing.isLoading} dataSource={listing.data?.items??[]} pagination={{current:page,pageSize:20,total:listing.data?.total??0,onChange:setPage}} columns={[
      {title:'名称',dataIndex:'name'},{title:'令牌前缀',dataIndex:'token_prefix'},
      {title:'默认模式',render:(_:unknown,x:EnrollmentToken)=><Tag>{label(modes,x.default_mode)}</Tag>},
      {title:'允许产品',render:(_:unknown,x:EnrollmentToken)=>x.allowed_products?.length?x.allowed_products.map(v=>label(products,v)).join('、'):'全部产品'},
      {title:'最大端点数',dataIndex:'max_endpoints'},{title:'有效期',render:(_:unknown,x:EnrollmentToken)=>time(x.expires_at)},
      {title:'状态',render:(_:unknown,x:EnrollmentToken)=><Tag color={x.enabled?'green':'default'}>{x.enabled?'有效':'已吊销'}</Tag>},
      {title:'操作',render:(_:unknown,x:EnrollmentToken)=>x.enabled?<Button danger size="small" onClick={()=>Modal.confirm({title:'确定吊销注册令牌？',onOk:()=>revoke.mutateAsync(x.id)})}>吊销</Button>:null},
    ]}/></Card>
    <Modal title="创建注册令牌" open={showCreate} onCancel={()=>setShowCreate(false)} onOk={()=>form.submit()} confirmLoading={create.isPending} destroyOnHidden>
      <Form form={form} layout="vertical" initialValues={{default_mode:'monitor',max_endpoints:1}} onFinish={values=>create.mutate({name:values.name,default_mode:values.default_mode,allowed_products:values.allowed_products??[],max_endpoints:values.max_endpoints,expires_at:values.expires_at?.toISOString()??null})}>
        <Form.Item label="名称" name="name" rules={[{required:true,message:'请输入名称'}]}><Input maxLength={80}/></Form.Item>
        <Form.Item label="默认模式" name="default_mode"><Select options={modes}/></Form.Item>
        <Form.Item label="允许产品" name="allowed_products"><Select mode="multiple" options={products} placeholder="不选择表示全部产品"/></Form.Item>
        <Form.Item label="最大端点数" name="max_endpoints" rules={[{required:true,message:'请输入数量'}]}><InputNumber min={0} precision={0} style={{width:'100%'}} /></Form.Item>
        <Form.Item label="有效期" name="expires_at"><DatePicker showTime style={{width:'100%'}} /></Form.Item>
      </Form>
    </Modal>
    <Modal title="注册令牌（仅本次显示）" open={secretVisible(created)} onCancel={()=>setCreated(null)} onOk={()=>setCreated(null)} destroyOnHidden>
      <Alert showIcon type="warning" message="关闭后无法再次查看令牌明文。请勿在公开渠道传播。" style={{marginBottom:12}} />
      <Typography.Paragraph copyable={{text:created?.token}} code>{created?.token}</Typography.Paragraph>
      <Typography.Text type="secondary">安装包及校验信息以 <a href="/agent-kit/" target="_blank" rel="noopener noreferrer">已部署端侧组件</a> 为准；未发布时请勿执行以下命令。</Typography.Text><br />
      <Typography.Text strong>插件接入命令</Typography.Text><Typography.Paragraph copyable={{text:command}} code>{command}</Typography.Paragraph>
      <Typography.Text strong>探针接入命令</Typography.Text><Typography.Paragraph copyable={{text:probe}} code>{probe}</Typography.Paragraph>
    </Modal>
  </div>
}
