'use strict';
// Discord credentials stay exclusively in process environment. No external packages.
const http = require('node:http');
const crypto = require('node:crypto');
const { URL, URLSearchParams } = require('node:url');
const random = () => crypto.randomBytes(32).toString('base64url');
const digest = x => crypto.createHash('sha256').update(x).digest('base64url');
const now = () => Date.now();
const LOGIN_MS = 10 * 60_000, SESSION_MS = 12 * 60 * 60_000;

function makeServer(config, fetcher = global.fetch) {
  const base = new URL(config.publicUrl);
  if (base.protocol !== 'https:' || base.username || base.password || base.pathname !== '/' || base.search || base.hash) throw new Error('PUBLIC_URL must be an HTTPS origin');
  if (!/^\d{15,22}$/.test(config.clientId) || !/^\d{15,22}$/.test(config.guildId) || !config.clientSecret || !config.botToken) throw new Error('Discord configuration missing or invalid');
  const callback = new URL('/oauth/callback', base).href;
  const flows = new Map(), byState = new Map(), sessions = new Map(), limits = new Map();
  function cleanup() {
    const t = now();
    for (const [key,flow] of flows) if(flow.expires <= t) { flows.delete(key); byState.delete(flow.state); }
    for (const [key,s] of sessions) if(s.expires<=t) sessions.delete(key);
    for (const [ip,r] of limits) if(r.until<=t) limits.delete(ip);
  }
  const timer=setInterval(cleanup, 60_000); timer.unref();
  const send=(res,status,value) => {res.writeHead(status, {'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'});res.end(JSON.stringify(value));};
  const html=(res,status,content) => {res.writeHead(status,{'content-type':'text/html; charset=utf-8','cache-control':'no-store','referrer-policy':'no-referrer','content-security-policy':"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",'x-content-type-options':'nosniff'});res.end(`<!doctype html><meta name="viewport" content="width=device-width"><title>Akuma</title><style>body{font:18px sans-serif;background:#101116;color:white;max-width:40em;margin:5em auto;padding:1em}</style><h1>Akuma</h1><p>${content}</p>`);};
  async function read(req) { let raw=''; for await (const chunk of req) { raw+=chunk; if(raw.length>4096) throw Error('body too large'); } const obj=JSON.parse(raw || '{}'); if(!obj || typeof obj!=='object' || Array.isArray(obj)) throw Error('invalid'); return obj; }
  async function discord(path, options={}) { return fetcher('https://discord.com/api/v10'+path,{...options,signal:AbortSignal.timeout(8000),redirect:'error'}); }
  async function membership(id) {
    try {
      const r=await discord(`/guilds/${config.guildId}/members/${id}`,{headers:{Authorization:'Bot '+config.botToken}});
      if(r.ok) return 'member';
      if(r.status===404) { const body=await r.json().catch(()=>({})); if(body.code===10007) return 'not_member'; }
      return 'unavailable';
    } catch {return 'unavailable';}
  }
  async function issue(flow) {
    const status=await membership(flow.id);
    if(status!=='member') return {status};
    if(sessions.size>=5000) return {status:'unavailable'};
    const token=random(); sessions.set(digest(token),{id:flow.id,name:flow.name,expires:now()+SESSION_MS});
    flows.delete(flow.key); byState.delete(flow.state);
    return {status:'ok',token,username:flow.name};
  }
  const server=http.createServer(async(req,res)=>{
    try {
      cleanup();
      // On Render, all clients can share a proxy IP; this is intentionally a coarse global guard, not identity.
      const ip=req.socket.remoteAddress || 'unknown'; let bucket=limits.get(ip);
      if(!bucket || bucket.until<=now()) {bucket={count:0,until:now()+60_000};limits.set(ip,bucket);}
      if(++bucket.count>600) return send(res,429,{error:'rate_limited'});
      const url=new URL(req.url,base);
      if(req.method==='GET' && url.pathname==='/health') return send(res,200,{status:'ok'});
      if(req.method==='GET' && url.pathname==='/oauth/callback') {
        const state=url.searchParams.get('state') || ''; const key=byState.get(state); const flow=flows.get(key);
        if(!flow || flow.status!=='pending' || flow.expires<=now()) return html(res,400,'This sign-in has expired. Return to Akuma and try again.');
        byState.delete(state); flow.status='processing';
        const code=url.searchParams.get('code');
        if(url.searchParams.get('error') || !code || url.searchParams.get('iss')!=='https://discord.com') {flow.status='failed'; return html(res,400,'Sign-in was cancelled or could not be verified. Return to Akuma.');}
        try {
          const form=new URLSearchParams({client_id:config.clientId,client_secret:config.clientSecret,grant_type:'authorization_code',code,redirect_uri:callback,code_verifier:flow.verifier});
          const t=await discord('/oauth2/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:form});
          if(!t.ok) throw Error('token'); const tokens=await t.json(); if(typeof tokens.access_token!=='string') throw Error('token');
          const u=await discord('/users/@me',{headers:{Authorization:'Bearer '+tokens.access_token}}); if(!u.ok) throw Error('user'); const user=await u.json();
          if(!/^\d{15,22}$/.test(user.id) || typeof user.username!=='string') throw Error('user');
          flow.id=user.id; flow.name=user.username.slice(0,80); flow.status='ready';
          return html(res,200,'Discord sign-in complete. Return to Akuma; it will check server membership.');
        } catch {flow.status='failed';return html(res,503,'Discord sign-in failed. Return to Akuma and try again.');}
      }
      if(req.method!=='POST') return send(res,404,{error:'not_found'});
      const body=await read(req);
      if(url.pathname==='/begin') {
        if(flows.size>=5000) return send(res,503,{error:'unavailable'});
        const secret=random(), key=digest(secret), state=random(), verifier=random();
        const flow={key,state,verifier,status:'pending',expires:now()+LOGIN_MS}; flows.set(key,flow);byState.set(state,key);
        const auth=new URL('https://discord.com/oauth2/authorize'); auth.search=new URLSearchParams({client_id:config.clientId,response_type:'code',redirect_uri:callback,scope:'identify',state,code_challenge:digest(verifier),code_challenge_method:'S256'}).toString();
        return send(res,200,{flow:secret,authorizationUrl:auth.href});
      }
      if(url.pathname==='/poll') {
        if(typeof body.flow!=='string' || body.flow.length>100) return send(res,400,{error:'bad_request'});
        const flow=flows.get(digest(body.flow)); if(!flow) return send(res,401,{status:'expired'});
        if(flow.status==='failed') {flows.delete(flow.key); return send(res,200,{status:'failed'});}
        if(flow.status!=='ready') return send(res,200,{status:'pending'});
        // Serialize issuance for each flow to prevent duplicate sessions under parallel polls.
        flow.status='checking'; const result=await issue(flow); if(result.status!=='ok') flow.status='ready'; return send(res,200,result);
      }
      const token=(req.headers.authorization||'').replace(/^Bearer /,'');
      if(!/^[A-Za-z0-9_-]{43}$/.test(token)) return send(res,401,{status:'expired'});
      const key=digest(token), session=sessions.get(key);
      if(!session) return send(res,401,{status:'expired'});
      if(url.pathname==='/logout') {sessions.delete(key);return send(res,200,{status:'ok'});}
      if(url.pathname==='/session') { const status=await membership(session.id); if(status==='not_member') sessions.delete(key); return send(res,200,{status,username:status==='member'?session.name:undefined}); }
      return send(res,404,{error:'not_found'});
    } catch { if(!res.headersSent) send(res,400,{error:'bad_request'}); else res.end(); }
  });
  server.on('close',()=>clearInterval(timer)); return server;
}
if(require.main===module) {
  const server=makeServer({publicUrl:process.env.PUBLIC_URL,clientId:process.env.DISCORD_CLIENT_ID,clientSecret:process.env.DISCORD_CLIENT_SECRET,botToken:process.env.DISCORD_BOT_TOKEN,guildId:process.env.DISCORD_GUILD_ID});
  server.listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log('Akuma auth server ready'));
}
module.exports={makeServer};
