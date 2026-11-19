import http from 'node:http';
import path from 'node:path';
import { appendFileSync } from 'node:fs';
import { once } from 'node:events';
import { Readable } from 'node:stream';
import { pathToFileURL } from 'node:url';
import { createMcpHandler } from '@modelcontextprotocol/server';
import { build } from './mcp-server.mjs';
import { runtime } from './runtime.mjs';
import { createHandler } from './http.mjs';

const revisions=['2026-07-28','2025-11-25'];
const prefix='io.modelcontextprotocol/';
const embeddedReceipt=s=>[...s.matchAll(/[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g)].some(([token])=>{try {return JSON.parse(Buffer.from(token.split('.')[0],'base64url').toString()).typ==='approval-receipt+jwt';}catch{return false;}});
const receiptKey=k=>k==='approval_receipt' || k==='receipt' || k.endsWith('/receipt');
// Redact receipt fields, copies elsewhere in the same request, and embedded JWSs.
function sanitize(value,context=value) {
  const receipts=new Set();
  function collect(v) {
    if (!v || typeof v!=='object') return;
    for (const [k,x] of Object.entries(v)) {
      if (receiptKey(k)) for (const s of Array.isArray(x)?x:[x]) if (typeof s==='string' && s) receipts.add(s);
      collect(x);
    }
  }
  collect(context);
  function clean(v,key='') {
    if (typeof v==='string' && (receiptKey(key) || [...receipts].some(s=>v.includes(s)) || embeddedReceipt(v))) return v.length;
    if (Array.isArray(v)) return v.map(x=>clean(x,key));
    if (v && typeof v==='object') return Object.fromEntries(Object.entries(v).map(([k,x])=>[k,clean(x,k)]));
    return v;
  }
  return clean(value);
}
function outcome(message) {
  if (message?.error) return 'refused:protocol_error';
  const result=message?.result;
  if (result?.resultType==='input_required' || result?.inputRequests) return 'input_required';
  if (result?.isError) {
    let approval=result._meta?.['com.example.approval/refusal'];
    if (!approval) try {approval=JSON.parse(result.content?.find(c=>c.type==='text')?.text);} catch {}
    return 'refused:'+(approval?.error ?? 'tool_error');
  }
  return result ? 'executed' : 'refused:transport_error';
}
function refusalOf(message) {
  const result=message?.result;
  if (result?.isError) {
    let approval=result._meta?.['com.example.approval/refusal'];
    if (!approval) try {approval=JSON.parse(result.content?.find(c=>c.type==='text')?.text);} catch {}
    return approval;
  }
}
export function createServer() {
  const token=process.env.VA_PATH_TOKEN;
  if (!token || token.length<24) throw Error('VA_PATH_TOKEN must contain at least 24 characters');
  if (!/^[A-Za-z0-9_-]+$/.test(token)) throw Error('VA_PATH_TOKEN must be a URL-safe token');
  process.env.VA_MODE ??= 'server';
  if (!['server','organization'].includes(process.env.VA_MODE)) throw Error('VA_MODE must be server or organization');
  const origin=new URL(process.env.VA_BASE_URL ?? `http://127.0.0.1:${process.env.PORT ?? 8787}`);
  if (!['http:','https:'].includes(origin.protocol) || origin.username || origin.password || origin.pathname!=='/' || origin.search || origin.hash) throw Error('VA_BASE_URL must be an HTTP(S) origin');
  process.env.VA_BASE_URL=origin.origin;
  const logFile=path.resolve(process.env.VA_LOG ?? './requests.log');
  if (!logFile.startsWith(process.cwd()+path.sep)) throw Error('VA_LOG must be inside this directory');
  process.env.VA_LOG=logFile; // the page handler appends its per-request lines to the same log
  const log=(event,context)=>appendFileSync(logFile,JSON.stringify({time:new Date().toISOString(),...sanitize(event,context)})+'\n');
  // Check log access before accepting requests. Logs are local synthetic test data.
  appendFileSync(logFile,'');
  const r=runtime(), pages=createHandler(r), seen=new Set();
  const mcp=createMcpHandler(()=>build(r),{legacy:'stateless'});
  const endpoint='/mcp/'+token;
  const server=http.createServer(async (req,res)=>{
    if (!req.url?.startsWith('/mcp')) return pages(req,res);
    if (req.url!==endpoint) {res.writeHead(404);res.end('Not found');return;}
    const abort=new AbortController();
    req.on('aborted',()=>abort.abort());
    res.on('close',()=>{if (!res.writableFinished) abort.abort();});
    const calls=new Map();
    let message, revision=null, clientInfo, capabilities;
    function observe(response) {
      if (!response || !Object.hasOwn(response,'id')) return;
      const call=calls.get(response.id);
      if (call) {const approval=refusalOf(response);log({...call,protocol_revision:revision,outcome:outcome(response),...(approval?.grant_status!==undefined?{grant_status:approval.grant_status}:{})},message);calls.delete(response.id);}
      if (response.result?.protocolVersion) revision=response.result.protocolVersion;
    }
    try {
      const chunks=[];let size=0;
      for await (const chunk of req) {size+=chunk.length;if(size>4*1024*1024){res.writeHead(413);res.end('Request too large');return;}chunks.push(chunk);}
      const body=Buffer.concat(chunks);
      try {message=JSON.parse(body.toString('utf8'));} catch {}
      const messages=Array.isArray(message)?message:[message];
      for (const m of messages) {
        const p=m?.params, meta=p?._meta;
        const claimed=meta?.[prefix+'protocolVersion'] ?? req.headers['mcp-protocol-version'];
        if (revisions.includes(claimed)) revision=claimed;
        clientInfo=meta?.[prefix+'clientInfo'] ?? p?.clientInfo ?? clientInfo;
        capabilities=meta?.[prefix+'clientCapabilities'] ?? p?.capabilities ?? capabilities;
        if (m?.method==='tools/call') calls.set(m.id,{event:'tools/call',tool:p?.name,arguments:p?.arguments ?? {},_meta:meta ?? {},...(p?.inputResponses!==undefined?{inputResponses:p.inputResponses}:{})});
      }
      const headers=new Headers();for(let i=0;i<req.rawHeaders.length;i+=2)headers.append(req.rawHeaders[i],req.rawHeaders[i+1]);
      const request=new Request('http://127.0.0.1'+req.url,{method:req.method,headers,signal:abort.signal,...(!['GET','HEAD'].includes(req.method)?{body}: {})});
      const response=await mcp.fetch(request);
      if(response.status>=400)revision=null;
      const sse=response.headers.get('content-type')?.startsWith('text/event-stream');
      res.writeHead(response.status,Object.fromEntries(response.headers));
      let text='',buffer='';const decoder=new TextDecoder();
      function consume(chunk,flush=false) {
        const decoded=decoder.decode(chunk,{stream:!flush});
        if (!sse) {text+=decoded;return;}
        buffer+=decoded;const frames=buffer.split(/\r?\n\r?\n/);buffer=frames.pop();
        for(const frame of frames) {
          const data=frame.split(/\r?\n/).filter(line=>line.startsWith('data:')).map(line=>line.slice(5).trimStart()).join('\n');
          if(data)try {observe(JSON.parse(data));}catch(e){if(e.code)throw e;}
        }
      }
      if(response.body)for await(const chunk of Readable.fromWeb(response.body)) {
        consume(chunk);if(!res.write(chunk))await once(res,'drain',{signal:abort.signal});
      }
      consume(undefined,true);
      if(!sse && text) {let parsed;try{parsed=JSON.parse(text);}catch{}for(const m of Array.isArray(parsed)?parsed:[parsed])observe(m);}
      if(clientInfo!==undefined || capabilities!==undefined) {
        const identity={protocol_revision:revision,client_info:clientInfo ?? null,capabilities:capabilities ?? {}};
        const key=JSON.stringify(sanitize(identity,message));
        if(!seen.has(key)) {log({event:'client',...identity},message);seen.add(key);}
      }
      for(const call of calls.values())log({...call,protocol_revision:revision,outcome:'refused:transport_error'},message);
      calls.clear();res.end();
    } catch {
      for(const call of calls.values())log({...call,protocol_revision:revision,outcome:'refused:transport_error'},message);
      if(!res.headersSent)res.writeHead(500,{'content-type':'text/plain'});
      res.end('HTTP request failed');
    }
  });
  server.on('close',()=>{mcp.close().finally(()=>r.sor.close());});
  return server;
}
if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  try {
    const server=createServer();
    server.on('error',()=>{console.error('Unable to bind the local HTTP listener');process.exitCode=1;server.close();});
    server.listen(Number(process.env.PORT ?? 8787),'127.0.0.1',()=>console.log(`MCP HTTP listening on 127.0.0.1:${server.address().port}`));
    for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>{server.close();server.closeAllConnections();});
  } catch(e) {console.error(e.message);process.exitCode=1;}
}
