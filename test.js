'use strict';
const test=require('node:test'); const assert=require('node:assert/strict'); const {makeServer}=require('./server');
const config={publicUrl:'https://akuma-test.onrender.com',clientId:'123456789012345678',clientSecret:'fake-secret',botToken:'fake-bot-token',guildId:'1558780910634147892'};
test('OAuth flow, membership, session and logout',async t=>{
  let member='not_member', tokens=0;
  async function fake(url,opts) {
    if(url.endsWith('/oauth2/token')) {tokens++;assert.match(String(opts.body),/code_verifier=/);return Response.json({access_token:'fake-access'});}
    if(url.endsWith('/users/@me')) return Response.json({id:'123456789012345679',username:'Test User'});
    if(url.includes('/guilds/')) {
      assert.equal(opts.headers.Authorization,'Bot fake-bot-token');
      if(member==='not_member') return Response.json({code:10007},{status:404});
      if(member==='unavailable') return Response.json({code:10004},{status:404});
      return Response.json({user:{id:'123456789012345679'}});
    }
    throw Error('unexpected');
  }
  const server=makeServer(config,fake);await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>server.close());const base=`http://127.0.0.1:${server.address().port}`;
  const post=async(path,body,token)=>{const r=await fetch(base+path,{method:'POST',headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:JSON.stringify(body)});return [r.status,await r.json()];};
  const [,begin]=await post('/begin',{});assert.equal(begin.flow.length,43);let auth=new URL(begin.authorizationUrl);assert.equal(auth.host,'discord.com');assert.equal(auth.searchParams.get('scope'),'identify');assert.equal(auth.searchParams.get('code_challenge_method'),'S256');
  let [,p]=await post('/poll',{flow:begin.flow});assert.equal(p.status,'pending');
  assert.equal((await post('/poll',{flow:'invalid'}))[0],401);
  const state=auth.searchParams.get('state'); let cb=await fetch(base+`/oauth/callback?state=${state}&code=mock&iss=${encodeURIComponent('https://discord.com')}`);assert.equal(cb.status,200);assert.equal(tokens,1);
  cb=await fetch(base+`/oauth/callback?state=${state}&code=mock&iss=${encodeURIComponent('https://discord.com')}`);assert.equal(cb.status,400);
  [,p]=await post('/poll',{flow:begin.flow});assert.equal(p.status,'not_member');
  member='unavailable';[,p]=await post('/poll',{flow:begin.flow});assert.equal(p.status,'unavailable');
  member='member';[,p]=await post('/poll',{flow:begin.flow});assert.equal(p.status,'ok');assert.equal(p.username,'Test User');const token=p.token;
  assert.equal((await post('/poll',{flow:begin.flow}))[0],401);
  [,p]=await post('/session',{},token);assert.equal(p.status,'member');
  member='not_member';[,p]=await post('/session',{},token);assert.equal(p.status,'not_member');assert.equal((await post('/session',{},token))[0],401);
  const [,b2]=await post('/begin',{});auth=new URL(b2.authorizationUrl);await fetch(base+`/oauth/callback?state=${auth.searchParams.get('state')}&code=mock&iss=${encodeURIComponent('https://discord.com')}`);member='member';const [,login2]=await post('/poll',{flow:b2.flow});assert.equal(login2.status,'ok');await post('/logout',{},login2.token);assert.equal((await post('/session',{},login2.token))[0],401);
});
test('rejects bad configuration',()=>{assert.throws(()=>makeServer({...config,publicUrl:'http://example.com'}));assert.throws(()=>makeServer({...config,botToken:''}));});
