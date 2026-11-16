/* Agent Config Check — no network, no execution, no dependencies. MIT. */
(function (root) {
'use strict';
const RULES = {
 SECRET:['high','Possible embedded credential','疑似内嵌凭据','Replace literal credentials with your client’s supported secret/input mechanism. Rotate any credential that was publicly exposed.','使用客户端支持的安全输入或环境引用；已公开的凭据需要轮换。'],
 HTTP:['medium','Unencrypted remote transport','远程连接未加密','Use HTTPS where supported; a local HTTP service still needs its own access controls.','优先使用 HTTPS；本地服务仍需访问控制。'],
 URL_AUTH:['high','Credential-like URL components','URL 含认证或查询信息','Avoid credentials in URLs. Query parameters may include secrets; review them privately.','避免在 URL 中放凭据；私下检查查询参数。'],
 SHELL:['medium','Shell interpreter in launch command','启动命令调用 Shell','Review the complete command offline. Shell commands can execute arbitrary code.','离线审核完整命令；Shell 可执行任意代码。'],
 PIPE:['high','Download-to-shell pattern','下载内容直接交给 Shell','Download, verify provenance and inspect scripts before any execution.','执行前先下载、验证来源并检查脚本。'],
 PRIVILEGE:['high','Elevated execution marker','提权执行标记','Avoid administrative privileges unless strictly necessary and independently reviewed.','非必要勿提权，先独立审核。'],
 UNPINNED:['medium','Package launcher needs version review','包启动器需核对固定版本','Pin and verify the package version and integrity. A pin alone does not prove trust.','固定并验证包版本及完整性；固定版本不代表可信。'],
 EXEC:['info','Local executable configured','配置了本地执行程序','Inspect the selected program and its arguments before allowing your client to launch it.','允许客户端启动前检查程序和参数。'],
 HOOK:['medium','Automatic hook configured','配置了自动 Hook','Hooks may run automatically. Inspect their code and triggering events.','Hook 可能自动运行，请检查代码和触发条件。'],
 BROAD:['high','Broad permission allowance','宽泛的权限放行','Reduce permissions to the minimum required; verify effective policy in the actual client.','缩小权限，并在实际客户端核对生效策略。'],
 BYPASS:['high','Approval bypass configuration','跳过审批配置','Review why approvals are bypassed and use the client’s safer approval mode.','检查跳过审批的原因，采用更安全的审批模式。'],
 SHAPE:['medium','Unsupported or invalid configuration field','字段结构无效或未支持','Consult the client schema. This field could not be assessed reliably.','对照客户端文档；此字段无法可靠检查。']
};
function strictJSON(text) {
 if(typeof text!=='string'||new TextEncoder().encode(text).byteLength>1048576) throw Error('Use a UTF-8 JSON file up to 1 MiB.');
 text=text.replace(/^\uFEFF/,''); let i=0;
 function ws(){while(/[ \t\r\n]/.test(text[i]||'')&&i<text.length)i++;}
 function str(){let start=i++;while(i<text.length){if(text[i]==='\\'){i+=2;continue;} if(text[i++]==='"')return JSON.parse(text.slice(start,i));}throw Error('Unterminated string.');}
 function value(d){ws();if(d>64)throw Error('JSON nesting exceeds 64 levels.');let c=text[i]; if(c==='"')return str();if(c==='{'||c==='['){i++;let obj=c==='{'?Object.create(null):[],seen=new Set(),end=c==='{'?'}':']';ws();if(text[i]===end){i++;return obj;}while(i<text.length){if(c==='{'){ws();if(text[i]!=='"')throw Error('Expected a quoted key.');let k=str();if(seen.has(k))throw Error('Duplicate JSON keys are not accepted.');seen.add(k);ws();if(text[i++]!==':')throw Error('Expected colon.');obj[k]=value(d+1);}else obj.push(value(d+1));ws();let sep=text[i++];if(sep===end)return obj;if(sep!==',')throw Error('Expected comma.');}throw Error('Incomplete JSON.');}let m=text.slice(i).match(/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/);if(!m)throw Error('Invalid JSON value.');i+=m[0].length;let v=JSON.parse(m[0]);if(typeof v==='number'&&!Number.isFinite(v))throw Error('Non-finite numbers are not accepted.');return v;}
 let out=value(0);ws();if(i!==text.length)throw Error('Unexpected JSON content. JSONC/TOML are not supported.');if(!out||Array.isArray(out)||typeof out!=='object')throw Error('Expected a JSON object.');return out;
}
function scan(text){const data=strictJSON(text), findings=[],formats=[];let nodes=0;const findingKeys=new Set();
 const add=(id,location)=>{const key=id+'|'+location;if(!findingKeys.has(key)){findingKeys.add(key);findings.push({id,severity:RULES[id][0],location});}};
 const obj=x=>x&&typeof x==='object'&&!Array.isArray(x);
 const ref=v=>/^\$\{[^}]+\}$/.test(v)||/^\$[A-Z_][A-Z0-9_]*$/.test(v)||/^<[^>]+>$/.test(v);
 function secrets(x,p){if(!obj(x)&&!Array.isArray(x))return;Object.entries(x).forEach(([k,v],idx)=>{if(++nodes>30000)throw Error('Too many JSON values.');let loc=p+'/'+(Array.isArray(x)?idx:'field-'+(idx+1));if(typeof v==='string'&&v&&!ref(v)&&(/(?:token|password|secret|api.?key|authorization|credential)/i.test(k)||/(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{16,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/.test(v)))add('SECRET',loc);if(obj(v)||Array.isArray(v))secrets(v,loc);});}
 secrets(data,'root');
 function command(cmd,args,loc){if(typeof cmd!=='string'||(args!==undefined&&(!Array.isArray(args)||args.some(a=>typeof a!=='string')))){add('SHAPE',loc);return;}add('EXEC',loc);let executable=cmd.trim().match(/^(?:"([^"]+)"|'([^']+)'|([^\s]+))/);let base=(executable?(executable[1]||executable[2]||executable[3]):cmd).split(/[\\/]/).pop().toLowerCase().replace(/\.(exe|cmd|bat)$/,'');let joined=[cmd,...(args||[])].join(' ');if(/^(?:ba|z|fi|da)?sh$|^(?:cmd|powershell|pwsh)$/.test(base))add('SHELL',loc);if(/\b(?:curl|wget)\b[\s\S]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|powershell|pwsh)\b/i.test(joined))add('PIPE',loc);if(/\b(?:sudo|runas)\b|--privileged\b/.test(joined))add('PRIVILEGE',loc);if(['npx','npm','pnpm','yarn','uvx','uv','pipx'].includes(base))add('UNPINNED',loc);}
 function servers(map,label){formats.push(label);if(!obj(map)){add('SHAPE',label);return;}Object.values(map).forEach((s,j)=>{let p=label+'/server-'+(j+1);if(!obj(s)){add('SHAPE',p);return;}if(s.disabled===true)return; if(s.command!==undefined)command(s.command,s.args,p+'/command');if(s.url!==undefined){if(typeof s.url!=='string'){add('SHAPE',p+'/url');return;}try{let u=new URL(s.url);if(u.protocol==='http:'&&!['localhost','127.0.0.1','[::1]'].includes(u.hostname))add('HTTP',p+'/url');if(!['http:','https:'].includes(u.protocol))add('SHAPE',p+'/url');if(u.username||u.password||u.search)add('URL_AUTH',p+'/url');}catch{add('SHAPE',p+'/url');}}if(s.command===undefined&&s.url===undefined)add('SHAPE',p);if(s.command!==undefined&&s.url!==undefined)add('SHAPE',p);});}
 if(Object.hasOwn(data,'mcpServers'))servers(data.mcpServers,'mcpServers');
 if(Object.hasOwn(data,'servers'))servers(data.servers,'servers');
 if(Object.hasOwn(data,'permissions')){formats.push('permissions');let p=data.permissions;if(!obj(p))add('SHAPE','permissions');else {if(p.defaultMode==='bypassPermissions')add('BYPASS','permissions/defaultMode');if(p.allow!==undefined){if(!Array.isArray(p.allow)||p.allow.some(v=>typeof v!=='string'))add('SHAPE','permissions/allow');else p.allow.forEach((v,i)=>{if(v==='*'||/^(Bash|Edit|Write|Read|WebFetch|mcp__.*)(\(\*\))?$/.test(v)||/^Bash\((?:\*|.*:\*)\)$/.test(v))add('BROAD','permissions/allow/'+i);});}}}
 if(Object.hasOwn(data,'hooks')){formats.push('hooks');if(!obj(data.hooks))add('SHAPE','hooks');else Object.values(data.hooks).forEach((events,i)=>{let p='hooks/event-'+(i+1);if(!Array.isArray(events)){add('SHAPE',p);return;}events.forEach((event,j)=>{if(!obj(event)||!Array.isArray(event.hooks)){add('SHAPE',p+'/'+j);return;}event.hooks.forEach((h,k)=>{let q=p+'/'+j+'/'+k;add('HOOK',q);if(obj(h)&&h.type==='command')command(h.command,undefined,q);});});});}
 findings.sort((a,b)=>['high','medium','info'].indexOf(a.severity)-['high','medium','info'].indexOf(b.severity));
 return {schema:'agent-config-check/1',version:'0.1.0',formats,coverage:formats.length?'partial-static-review':'unrecognized-format',findings,counts:{high:findings.filter(x=>x.severity==='high').length,medium:findings.filter(x=>x.severity==='medium').length,info:findings.filter(x=>x.severity==='info').length},limitations:['Heuristic review only; not a security certification.','No commands executed, network requests sent, credentials validated or effective policy resolved.','Locations omit user keys and values to reduce accidental disclosure. Map field-N to object insertion order.','Disabled MCP entries still receive generic secret checks. Unknown fields are not schema-validated.']};
}
const api={scan,strictJSON,RULES};if(typeof module!=='undefined')module.exports=api;else root.ConfigCheck=api;
})(typeof globalThis!=='undefined'?globalThis:this);
