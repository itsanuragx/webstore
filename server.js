import http from 'node:http';
import { readFile, writeFile, access } from 'node:fs/promises';
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const dbFile = path.join(root, 'data/store.local.json');
const seedFile = path.join(root, 'data/store.json');
const sessions = new Map();
const env = process.env;
const secret = env.SESSION_SECRET || randomBytes(32).toString('hex');
const isProd = env.NODE_ENV === 'production';

async function db() { try { await access(dbFile); return JSON.parse(await readFile(dbFile, 'utf8')); } catch { return JSON.parse(await readFile(seedFile, 'utf8')); } }
async function save(data) { await writeFile(dbFile, JSON.stringify(data, null, 2)); }
function json(res, code, data) { res.writeHead(code, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'}); res.end(JSON.stringify(data)); }
function parseCookies(req) { return Object.fromEntries((req.headers.cookie || '').split(';').map(x => x.trim().split('=')).filter(x=>x.length===2)); }
function signed(id) { return `${id}.${createHmac('sha256', secret).update(id).digest('hex')}`; }
function user(req) { const token=parseCookies(req).dm_session; if(!token) return null; const [id,sig]=token.split('.'); if(!id || !sig || !timingSafeEqual(Buffer.from(sig), Buffer.from(createHmac('sha256',secret).update(id).digest('hex')))) return null; const s=sessions.get(id); return s && s.expires > Date.now() ? s : null; }
function requireAdmin(req,res) { if(!user(req)) { json(res,401,{error:'Authentication required'}); return false; } return true; }
async function body(req) { let raw=''; for await(const c of req) { raw+=c; if(raw.length>1e6) throw Error('Request too large'); } return raw ? JSON.parse(raw) : {}; }
function safeText(value, max=180) { return typeof value==='string' ? value.trim().slice(0,max) : ''; }
function mime(file) { return ({'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'})[path.extname(file)] || 'application/octet-stream'; }

const server=http.createServer(async(req,res)=>{
  const url=new URL(req.url, `http://${req.headers.host}`); const method=req.method;
  try {
    if(url.pathname==='/api/store' && method==='GET') { const data=await db(); return json(res,200,{settings:data.settings,categories:data.categories,products:data.products.filter(p=>p.enabled)}); }
    if(url.pathname==='/api/admin/session' && method==='GET') return json(res,200,{authenticated:!!user(req)});
    if(url.pathname==='/api/status' && method==='GET') {
      try { const r=await fetch('https://api.mcsrvstat.us/3/play.disastermc.fun',{signal:AbortSignal.timeout(3000)}); const s=await r.json(); return json(res,200,{online:!!s.online,players:s.players?.online||0,max:s.players?.max||100}); } catch { return json(res,200,{online:false,players:0,max:100}); }
    }
    if(url.pathname==='/api/admin/login' && method==='POST') {
      if(!env.ADMIN_PASSWORD_HASH) return json(res,503,{error:'Admin authentication is not configured. Set ADMIN_PASSWORD_HASH on the server.'});
      const {password}=await body(req); const candidate=scryptSync(String(password||''),'disastermc',64).toString('hex');
      if(!timingSafeEqual(Buffer.from(candidate),Buffer.from(env.ADMIN_PASSWORD_HASH))) return json(res,401,{error:'Invalid credentials'});
      const id=randomBytes(24).toString('hex'); sessions.set(id,{expires:Date.now()+1000*60*60*8}); res.setHeader('Set-Cookie',`dm_session=${signed(id)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${isProd?'; Secure':''}`); return json(res,200,{ok:true});
    }
    if(url.pathname==='/api/admin/logout' && method==='POST') { const token=parseCookies(req).dm_session; if(token) sessions.delete(token.split('.')[0]); res.setHeader('Set-Cookie','dm_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); return json(res,200,{ok:true}); }
    if(url.pathname==='/api/admin/store') {
      if(!requireAdmin(req,res)) return;
      if(method==='GET') return json(res,200,await db());
      if(method==='PUT') { const incoming=await body(req); const current=await db(); const categories=Array.isArray(incoming.categories)?incoming.categories.map((c,i)=>({id:safeText(c.id,40).replace(/[^a-z0-9-]/gi,'')||`category-${i}`,name:safeText(c.name,40),icon:safeText(c.icon,6)})):current.categories; const products=Array.isArray(incoming.products)?incoming.products.map((p,i)=>({id:safeText(p.id,50).replace(/[^a-z0-9-]/gi,'')||`product-${i}`,category:safeText(p.category,40),name:safeText(p.name,70),price:Number(p.price)||0,sale:p.sale===null||p.sale===''?null:Number(p.sale)||0,description:safeText(p.description,240),image:safeText(p.image,300)||'/assets/rank-ember.svg',enabled:!!p.enabled,order:Number(p.order)||i+1,badge:safeText(p.badge,30)})):current.products; const settings={...current.settings,...Object.fromEntries(Object.entries(incoming.settings||{}).map(([k,v])=>[k,safeText(v,300)]))}; const next={settings,categories,products}; await save(next); return json(res,200,next); }
    }
    let pathname=url.pathname==='/'?'/index.html':url.pathname; if(pathname==='/admin/login') pathname='/admin.html'; const file=path.resolve(root,'public','.'+pathname); if(!file.startsWith(path.join(root,'public'))) return json(res,403,{error:'Forbidden'}); const content=await readFile(file); res.writeHead(200,{'Content-Type':mime(file)}); res.end(content);
  } catch(e) { if(e.code==='ENOENT') return json(res,404,{error:'Not found'}); console.error(e); json(res,500,{error:'Server error'}); }
});
server.listen(Number(env.PORT)||3000,()=>console.log('DisasterMC Store running on http://localhost:3000'));
