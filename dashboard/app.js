'use strict';
const $=id=>document.getElementById(id);
const labels={running:'运行中',connected:'已连接',offline:'离线',stopped:'已停止',completed:'完成',reviewing:'等待 Codex 验收',needs_revision:'待修订',blocked:'阻塞',result_unknown:'结果未知，禁止盲重试',active:'执行中',failed:'失败',pending:'排队',degraded:'降级运行'};
const label=s=>labels[s]||s||'未知';
const errorLabel=s=>({provider_balance_insufficient:'模型服务余额不足，请处理账户额度',codex_model_unsupported:'协同模型与当前登录方式不兼容',codex_model_invalid:'协同模型配置无效'})[s]||s;
function el(tag,text,cls){const n=document.createElement(tag);n.textContent=text;if(cls)n.className=cls;return n}
function row(title,detail){const n=el('div',title,'row');n.append(el('small',detail));return n}
let loading=false;
async function refresh(){if(loading||!$('run').value)return;loading=true;const run=$('run').value;try{
 const r=await fetch('/api/status?run='+encodeURIComponent(run));if(!r.ok)throw Error('unavailable');const d=await r.json();if(run!==$('run').value)return;
 $('connection').textContent='看板已连接';$('updated').textContent='读取于 '+new Date(d.observed_at*1000).toLocaleString();
 const live=d.roles.filter(r=>!['offline','stopped'].includes(r.state)).length;
 $('online').textContent=live+' / 8';$('task-count').textContent=d.tasks.length;$('memory-count').textContent=(d.memory.events??'—')+' / '+(d.memory.verified_summaries??'—');
 $('notice').textContent=live===0?'当前选择的是已停止或不可核验的批次。以下是该批次留存记录，不代表系统正在常驻。':`本批次 ${live}/8 角色具备可信新鲜心跳。数据库：${d.database==='readable'?'可读':'不可用'}。`;
 if(['running','reconnecting'].includes(d.resident?.state)&&live>0){const fresh=d.observed_at-d.resident.updated_at<35;$('notice').textContent+=fresh?(d.resident.state==='reconnecting'?' 飞书断线重连中（最多等待 5 分钟），当前不保证收发；不重放任务。':' 常驻守护在线，租期至 '+new Date(d.resident.lease_end*1000).toLocaleString()+'；短时断线自动重连，超时收尾。'):' 常驻守护状态已过期，不能确认仍受监控，请勿重复启动。';}
 if(d.resident?.state==='cleanup_incomplete')$('notice').textContent+=' 警告：常驻收尾不完整，需要核对进程身份后处理，禁止直接重启。';
 $('roles').replaceChildren(...d.roles.map(r=>{const n=el('div','','role');n.append(el('b',r.role),el('span',label(r.state),r.state==='offline'?'muted':'ok'));if(r.connected)n.append(el('small',' · 长连接已建立'));return n}));
 $('tasks').replaceChildren(...(d.tasks.length?d.tasks.map(t=>{let state=label(t.display_state||t.state);if(t.task_id.startsWith('handoff-')&&t.state==='completed')state=t.revision===5?'Codex 验收通过':t.revision===3?'执行完成 · 尚未回 Codex 验收':state;return row(t.task_id,`${t.owner} · ${state}${t.blocked_reason?' · '+errorLabel(t.blocked_reason):''} · 版本 ${t.revision} · ${t.updated_at} UTC`)}):[el('p','该批次暂无任务','muted')]));
 $('calls').replaceChildren(...(d.calls.length?d.calls.map(c=>row(`${c.agent} · ${label(c.state)}`,`${c.started_at||'—'} UTC${c.error_code?' · '+errorLabel(c.error_code):''}`)):[el('p','暂无调用','muted')]));
 $('cursors').textContent=(d.memory.cursors||[]).map(c=>c.agent+'：已消费至 #'+c.last_consumed_event_seq).join(' / ');
 }catch(e){$('connection').textContent='读取失败';$('notice').textContent='状态读取失败，不能将之前的在线状态视为当前事实。';$('online').textContent='未知';}finally{loading=false}}
async function init(){try{const r=await fetch('/api/runs');if(!r.ok)throw Error();const d=await r.json();$('run').replaceChildren(...d.runs.map(id=>{const o=el('option',id);o.value=id;return o}));await refresh()}catch(e){$('connection').textContent='看板不可用'}}
$('run').addEventListener('change',refresh);$('refresh').addEventListener('click',refresh);init();setInterval(refresh,5000);
