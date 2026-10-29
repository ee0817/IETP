import sys,json,io,contextlib,subprocess,ast,argparse,os
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--out',required=True);a=p.parse_args()
SRC=Path(a.source).resolve();OUT=Path(a.out).resolve();OUT.mkdir(parents=True,exist_ok=True)
sys.dont_write_bytecode=True;sys.path.insert(0,str(SRC))
from events.security_event import SecurityEvent,SecurityStage
from core.shield import RAGFlowShield
from workflow.runner import WorkflowRunner
checks=[];records=[];traces=[]
def ev(stage='input',score=.1,kind='none',confidence=1,event_id=None):
 return SecurityEvent(SecurityStage(stage),score,kind,confidence,event_id=event_id)
def shield():return RAGFlowShield(total_budget=10,max_retries=3,max_rollbacks=2)
def call(s,e):
 r=s.process(e);traces.append({'input':e.to_dict(),'result':r,'state_after':s.risk_state.get_state(),'budget_after':s.risk_budget.get_state()});return r
def eq(x,y,msg=''):assert x==y,msg or f'expected {y!r}, actual {x!r}'
def close(x,y):assert abs(x-y)<1e-9,f'expected {y}, actual {x}'
def case(i,name,basis='现有策略'):
 def reg(fn):checks.append((i,name,basis,fn));return fn
 return reg
@case('S01','四阶段正常流程')
def t():
 s=shield()
 for st in ['input','retrieval','generation','output']:eq(call(s,ev(st))['decision']['action'],'CONTINUE')
 close(s.risk_budget.consumed_budget,.4)
@case('S02','输入注入阻断')
def t():eq(call(shield(),ev(score=.9,kind='prompt_injection'))['flow_action']['flow_action'],'terminate')
@case('S03','检索投毒回到输入检查点')
def t():
 s=shield();s.save_checkpoint('input',{'documents':[]});r=call(s,ev('retrieval',.8,'poisoned_document'))
 eq(r['rollback']['rollback_to'],'input');eq(r['rollback']['workflow_state']['documents'],[])
@case('S04','生成风险回到检索检查点')
def t():
 s=shield();s.save_checkpoint('retrieval',{'answer':None,'documents':['d1']});r=call(s,ev('generation',.7,'unsafe_generation'))
 eq(r['rollback']['rollback_to'],'retrieval');eq(r['rollback']['workflow_state']['answer'],None)
@case('S05','输出泄露回到检索检查点')
def t():
 s=shield();s.save_checkpoint('retrieval',{'answer':None});eq(call(s,ev('output',.7,'sensitive_information'))['rollback']['rollback_to'],'retrieval')
@case('S06','预算耗尽阻断')
def t():
 s=RAGFlowShield(total_budget=.5);eq(call(s,ev(score=.5))['decision']['action'],'BLOCK');eq(s.risk_budget.remaining_budget,0)
@case('S07','五阶段轻微风险累积')
def t():
 s=RAGFlowShield(total_budget=1)
 actions=[call(s,ev(k,.25,'minor_risk',.9))['decision']['action'] for k in ['input','retrieval','context','generation','output']]
 eq(actions,['CONTINUE','CONTINUE','CONTINUE','RESTRICT','BLOCK']);close(s.risk_budget.consumed_budget,1.125)
@case('S08','回滚恢复风险但不恢复预算','架构原则')
def t():
 s=shield();call(s,ev(score=.2,confidence=.9));s.save_checkpoint('retrieval',{'answer':None})
 call(s,ev('generation',.7,'unsafe_generation',.9));close(s.risk_state.global_risk,.2);close(s.risk_budget.consumed_budget,.81)
 eq(s.circuit_breaker.rollback_count,1);eq(s.circuit_breaker.retry_count,1)
@case('S09','持续生成风险触发熔断','架构原则')
def t():
 s=shield();s.save_checkpoint('retrieval',{})
 eq(call(s,ev('generation',.7,'unsafe_generation'))['flow_action']['flow_action'],'rollback')
 eq(call(s,ev('generation',.7,'unsafe_generation'))['flow_action']['flow_action'],'terminate');eq(s.circuit_breaker.rollback_count,2)
@case('S10','熔断后返回结构保持兼容','安全验收要求')
def t():
 s=shield();s.save_checkpoint('retrieval',{})
 for _ in range(2):call(s,ev('generation',.7,'unsafe_generation'))
 r=call(s,ev());eq(r.get('flow_action',{}).get('flow_action'),'terminate','熔断后缺少统一flow_action字段')
@case('S11','检查点保存使用深拷贝','架构原则')
def t():
 s=shield();w={'documents':[{'content':'safe'}]};s.save_checkpoint('retrieval',w);w['documents'][0]['content']='changed'
 eq(s.checkpoint_manager.rollback_to('retrieval')['workflow_state']['documents'][0]['content'],'safe')
@case('S12','不可信检查点不可恢复','架构原则')
def t():
 s=shield();s.save_checkpoint('retrieval',{},trusted=False);eq(s.checkpoint_manager.rollback_to('retrieval')['action'],'block')
@case('S13','缺失检查点时最终动作终止','安全验收要求')
def t():
 r=call(shield(),ev('generation',.7,'unsafe_generation'));eq(r['flow_action']['flow_action'],'terminate','内部返回block但外层仍是rollback')
@case('S14','相同事件重放不重复计费','安全验收要求')
def t():
 s=shield();e=ev(score=.2,event_id='duplicate-event');call(s,e);before=s.risk_budget.consumed_budget;call(s,e);close(s.risk_budget.consumed_budget,before)
@case('S15','同阶段较低分不覆盖较高分')
def t():
 s=shield();call(s,ev('retrieval',.7,'suspicious_document'));call(s,ev('retrieval',.1));close(s.risk_state.stage_risks['retrieval'],.7)
@case('S16','新增低风险阶段不稀释已有高风险','安全验收要求')
def t():
 s=shield();call(s,ev(score=.8,kind='suspicious_input'));before=s.risk_state.global_risk;call(s,ev('retrieval',.01))
 assert s.risk_state.global_risk>=before,f'全局风险从{before}降至{s.risk_state.global_risk}'
for i,score,state in [('S17',.299,'NORMAL'),('S18',.3,'CAUTIOUS'),('S19',.6,'RESTRICTED'),('S20',.85,'BLOCKED')]:
 def boundary(score=score,state=state):eq(call(shield(),ev(score=score))['risk_state'],state)
 checks.append((i,'状态边界 '+str(score),'现有阈值',boundary))
@case('S21','零分泄露类型不应触发回滚','组员接口兼容要求')
def t():
 s=shield();s.save_checkpoint('retrieval',{});eq(call(s,ev('output',0,'sensitive_information'))['decision']['action'],'CONTINUE')
@case('S22','错误阶段在构造时拒绝','安全验收要求')
def t():
 try:SecurityEvent('invalid',.1,'none',1)
 except (TypeError,ValueError):return
 raise AssertionError('SecurityEvent接受非法stage')
@case('S23','非法风险分在构造时拒绝','现有校验')
def t():
 for v in [-.1,1.1,float('nan'),float('inf')]:
  try:ev(score=v)
  except (TypeError,ValueError):continue
  raise AssertionError('非法风险分被接受')
@case('S24','非法置信度在构造时拒绝','现有校验')
def t():
 for v in [-.1,1.1,float('nan'),float('inf')]:
  try:ev(confidence=v)
  except (TypeError,ValueError):continue
  raise AssertionError('非法置信度被接受')
@case('S25','缺失检测结果得到受控处理','安全验收要求')
def t():
 try:r=shield().process(None)
 except Exception as ex:raise AssertionError('缺失结果导致未处理异常 '+type(ex).__name__)
 assert r.get('flow_action',{}).get('flow_action') in ['terminate','verification']
@case('S26','独立请求实例交错执行不串状态','独立实例使用约定')
def t():
 a,b=shield(),shield();call(a,ev(score=.5));call(b,ev(score=.1));call(a,ev('retrieval',.3))
 close(b.risk_state.global_risk,.1);close(b.risk_budget.consumed_budget,.1)
@case('S27','同一Runner连续请求不沿用预算','请求生命周期验收要求')
def t():
 r=WorkflowRunner()
 with contextlib.redirect_stdout(io.StringIO()):r.run('request-A')
 first=r.shield.risk_budget.consumed_budget
 with contextlib.redirect_stdout(io.StringIO()):r.run('request-B')
 close(r.shield.risk_budget.consumed_budget,first)
@case('S28','已有Runner演示完成回滚重跑','现有演示流程')
def t():
 r=WorkflowRunner();f=io.StringIO()
 with contextlib.redirect_stdout(f):r.run('什么是RAG')
 assert 'WORKFLOW FINISHED' in f.getvalue();eq(r.shield.circuit_breaker.rollback_count,1);assert r.workflow_state['answer']
@case('S29','回滚返回状态与内部状态一致','返回契约验收要求')
def t():
 s=shield();call(s,ev(score=.1));s.save_checkpoint('retrieval',{});r=call(s,ev('generation',.7,'unsafe_generation'))
 eq(r['risk_state'],s.risk_state.state,'返回值仍为回滚前风险，缺少前后状态区分')
@case('S30','低预算不降低已阻断风险等级','安全验收要求')
def t():eq(call(RAGFlowShield(total_budget=1.1),ev(score=.9,kind='suspicious_input'))['decision']['action'],'BLOCK')
@case('S31','多文档事件可关联文档和检测器','接口能力验收要求')
def t():
 try:SecurityEvent(SecurityStage.RETRIEVAL,.5,'suspicious_document',.9,chunk_id='d2',detector_name='test')
 except TypeError:raise AssertionError('事件尚不支持chunk_id和detector_name')
@case('S32','复核动作实际执行后才输出','流程执行验收要求')
def t():
 r=WorkflowRunner();original=r.shield.process;seen=[]
 def inject(e):
  if e.stage==SecurityStage.GENERATION:e.risk_type='suspicious_generation';e.risk_score=.4
  result=original(e);seen.append(result);return result
 r.shield.process=inject;f=io.StringIO()
 with contextlib.redirect_stdout(f):r.run('verify-test')
 assert any(x['flow_action']['flow_action']=='verification' for x in seen)
 assert 'FINAL ANSWER' not in f.getvalue(),'Runner收到verification仍直接输出，未执行复核'
for i,name,basis,fn in checks:
 traces=[];status='PASS';error=''
 try:fn()
 except Exception as ex:status='FAIL';error=type(ex).__name__+': '+str(ex)
 records.append(dict(id=i,name=name,basis=basis,status=status,error=error,trace=traces));print(i,status,name)
legacy=[]
for path in sorted((SRC/'test').glob('test_*.py')):
 tree=ast.parse(path.read_text(encoding='utf-8-sig'));asserts=sum(isinstance(n,ast.Assert) for n in ast.walk(tree))
 try:
  r=subprocess.run([sys.executable,'-B',str(path)],cwd=str(SRC),env=dict(os.environ,PYTHONPATH=str(SRC),PYTHONIOENCODING='utf-8'),capture_output=True,text=True,encoding='utf-8',timeout=10)
  status='EXIT_OK' if r.returncode==0 else 'ERROR';log=r.stdout+'\n'+r.stderr
 except subprocess.TimeoutExpired:status='TIMEOUT';log='timeout 10s'
 legacy.append(dict(file=path.name,status=status,assert_count=asserts,log=log))
summary={'source':str(SRC),'scenario_pass':sum(x['status']=='PASS' for x in records),'scenario_fail':sum(x['status']=='FAIL' for x in records),'scenario_total':len(records),'legacy_exit_ok':sum(x['status']=='EXIT_OK' for x in legacy),'legacy_total':len(legacy),'note':'安全验收项失败表示设计或能力缺口；脚本退出成功不等于断言通过。'}
(OUT/'模拟测试详细结果.json').write_text(json.dumps(dict(summary=summary,scenarios=records,legacy=legacy),ensure_ascii=False,indent=2),encoding='utf-8')
md=['# 编排模块模拟事件测试报告','','## 范围与结果','','测试指定源码目录，不调用真实模型或检索器。现有策略项检查源码规则；安全验收项检查集成所需能力，相关设计仍需确认。',f"新增场景{len(records)}项，通过{summary['scenario_pass']}项，未通过{summary['scenario_fail']}项。",f"已有演示脚本{len(legacy)}个，正常退出{summary['legacy_exit_ok']}个。全部演示脚本的assert数量见下表，退出成功不能代替正确性验证。",'','## 场景结果','','|编号|场景|依据|结果|','|---|---|---|---|']
for x in records:md.append(f"|{x['id']}|{x['name']}|{x['basis']}|{x['status']}|")
md+=['','## 未通过场景','']
for x in records:
 if x['status']=='FAIL':md += [f"### {x['id']} {x['name']}",'',x['error'],'']
md+=['## 已有演示脚本','']
for x in legacy:
 md.append(f"- {x['file']}：{x['status']}，assert数量{x['assert_count']}。")
 if x['status']!='EXIT_OK':md+=['',x['log'][-1200:],'']
md+=['','## 限制','','S25仅测试缺失检测结果，未覆盖真实检测器超时。S26仅测试独立实例交错执行，不代表共享实例多线程隔离。S31报告多文档事件接口缺口，跨检测器语义去重尚未执行。本次执行不修改业务实现；被测版本包含已记录的修复。']
(OUT/'编排模块模拟测试报告.md').write_text('\n'.join(md),encoding='utf-8')
print(json.dumps(summary,ensure_ascii=False))

sys.exit(1 if summary["scenario_fail"] or any(x["status"]!="EXIT_OK" for x in legacy) else 0)
