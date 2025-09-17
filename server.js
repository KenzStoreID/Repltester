\
/* Combined server.js - see README for usage */
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const settings = require('./settings');

const app = express();
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
const PORT = 3000;

const USERS_FILE = path.join(__dirname, 'users.json');
const FAILED_LOG = path.join(__dirname, 'failed_log.json');

function safeLoadJson(p, fallback){
  try{ if(fs.existsSync(p)) return JSON.parse(fs.readFileSync(p,'utf8')); }catch(e){}
  fs.writeFileSync(p, JSON.stringify(fallback,null,2));
  return fallback;
}
let usersDb = safeLoadJson(USERS_FILE, {users: []});
safeLoadJson(FAILED_LOG, {failed: []});

if(usersDb.users.length && usersDb.users[0].passwordHash && usersDb.users[0].passwordHash.startsWith("$2a$10$u1q")){
  usersDb.users[0].passwordHash = bcrypt.hashSync('admin123', 10);
  fs.writeFileSync(USERS_FILE, JSON.stringify(usersDb, null, 2));
  console.log("Initialized default admin with username 'admin' and password 'admin123' (please change).");
}

const webSessions = {};

const GITHUB_API = `https://api.github.com/repos/${settings.GITHUB_REPO}/contents/${settings.GITHUB_FILE_PATH}`;
const GITHUB_RAW = `https://raw.githubusercontent.com/${settings.GITHUB_REPO}/main/${settings.GITHUB_FILE_PATH}`;

async function fetchNumbersRaw(){
  try{
    const r = await axios.get(GITHUB_RAW, { headers: { 'Cache-Control': 'no-cache' } });
    return Array.isArray(r.data) ? r.data : [];
  }catch(e){
    console.warn("Failed to fetch raw numbers:", e.message);
    return [];
  }
}

async function fetchFileSha(){
  try{
    const r = await axios.get(GITHUB_API, { headers: { Authorization: `token ${settings.GITHUB_PAT}` } });
    return r.data.sha;
  }catch(e){
    console.warn("Failed to fetch file sha:", e.message);
    return null;
  }
}

async function updateNumbersOnGithub(numbers){
  try{
    const sha = await fetchFileSha();
    if(!sha) throw new Error('no sha');
    const content = Buffer.from(JSON.stringify(numbers, null, 2)).toString('base64');
    const res = await axios.put(GITHUB_API, {
      message: `Update numbers by bot - ${new Date().toISOString()}`,
      content,
      sha
    }, { headers: { Authorization: `token ${settings.GITHUB_PAT}` } });
    return res.data;
  }catch(e){
    console.error("Error updating GitHub:", e.message);
    throw e;
  }
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/login', (req, res)=>{
  const { username, password } = req.body || {};
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const usr = usersDb.users.find(u=>u.username===username);
  if(!usr){
    const fl = safeLoadJson(FAILED_LOG, {failed: []});
    fl.failed.push({username, ip, time: new Date().toISOString()});
    fs.writeFileSync(FAILED_LOG, JSON.stringify(fl,null,2));
    return res.json({ success:false, message:'Invalid username or password' });
  }
  const ok = bcrypt.compareSync(password, usr.passwordHash);
  if(!ok){
    const fl = safeLoadJson(FAILED_LOG, {failed: []});
    fl.failed.push({username, ip, time: new Date().toISOString()});
    fs.writeFileSync(FAILED_LOG, JSON.stringify(fl,null,2));
    return res.json({ success:false, message:'Invalid username or password' });
  }
  const token = Math.random().toString(36).slice(2);
  webSessions[token] = { username, role: usr.role, created: Date.now() };
  return res.json({ success:true, token, username, role: usr.role });
});

app.get('/list-numbers', async (req, res)=>{
  const nums = await fetchNumbersRaw();
  res.json(nums);
});

app.post('/add-number', async (req, res)=>{
  const token = req.headers['x-session'];
  const session = webSessions[token];
  if(!session) return res.status(401).json({error:'not authorized'});
  const { number } = req.body || {};
  if(!/^\d+$/.test(number)) return res.status(400).json({error:'invalid number'});
  const nums = await fetchNumbersRaw();
  if(nums.includes(number)) return res.status(400).json({error:'already exists'});
  nums.push(number);
  try{
    await updateNumbersOnGithub(nums);
    notifyAdmins(`[WEB] ${session.username} added number: ${number}`);
    return res.json({ok:true});
  }catch(e){
    return res.status(500).json({error:'failed update'});
  }
});

app.post('/delete-number', async (req, res)=>{
  const token = req.headers['x-session'];
  const session = webSessions[token];
  if(!session) return res.status(401).json({error:'not authorized'});
  const { number } = req.body || {};
  const nums = await fetchNumbersRaw();
  const idx = nums.indexOf(number);
  if(idx===-1) return res.status(400).json({error:'not found'});
  nums.splice(idx,1);
  try{
    await updateNumbersOnGithub(nums);
    notifyAdmins(`[WEB] ${session.username} deleted number: ${number}`);
    return res.json({ok:true});
  }catch(e){
    return res.status(500).json({error:'failed update'});
  }
});

app.post('/add-user', (req, res)=>{
  const token = req.headers['x-session'];
  const session = webSessions[token];
  if(!session) return res.status(401).json({error:'not authorized'});
  if(session.role !== 'admin') return res.status(403).json({error:'admin only'});
  const { username, password, role } = req.body || {};
  if(!username || !password) return res.status(400).json({error:'missing'});
  if(usersDb.users.find(u=>u.username===username)) return res.status(400).json({error:'exists'});
  const hash = bcrypt.hashSync(password, 10);
  usersDb.users.push({username, passwordHash: hash, role: role || 'user'});
  fs.writeFileSync(USERS_FILE, JSON.stringify(usersDb,null,2));
  notifyAdmins(`[WEB] Admin ${session.username} added user ${username} (${role})`);
  res.json({ok:true});
});

app.post('/delete-user', (req, res)=>{
  const token = req.headers['x-session'];
  const session = webSessions[token];
  if(!session) return res.status(401).json({error:'not authorized'});
  if(session.role !== 'admin') return res.status(403).json({error:'admin only'});
  const { username } = req.body || {};
  const idx = usersDb.users.findIndex(u=>u.username===username);
  if(idx===-1) return res.status(400).json({error:'not found'});
  usersDb.users.splice(idx,1);
  fs.writeFileSync(USERS_FILE, JSON.stringify(usersDb,null,2));
  notifyAdmins(`[WEB] Admin ${session.username} deleted user ${username}`);
  res.json({ok:true});
});

app.get('/list-users', (req,res)=>{
  const token = req.headers['x-session'];
  const session = webSessions[token];
  if(!session) return res.status(401).json({error:'not authorized'});
  if(session.role !== 'admin') return res.status(403).json({error:'admin only'});
  res.json(usersDb.users.map(u=>({username:u.username, role:u.role})));
});

app.listen(PORT, ()=>{
  console.log(`Web server running at http://localhost:${PORT}`);
});

const TELE_BOT = settings.TELEGRAM_BOT_TOKEN;
if(!TELE_BOT || TELE_BOT.includes("REPLACE")){
  console.warn("Telegram token not set in settings.js - bot will not run.");
}else{
  console.log("Bot running... (polling)");
  let offset = 0;
  const tgSessions = {};
  const pending = {};

  async function pollTelegram(){
    try{
      const url = `https://api.telegram.org/bot${TELE_BOT}/getUpdates?offset=${offset}&timeout=20`;
      const r = await axios.get(url, {timeout:30000});
      const data = r.data;
      if(data && data.result && data.result.length){
        for(const upd of data.result){
          offset = upd.update_id + 1;
          if(!upd.message || !upd.message.text) continue;
          const chatId = upd.message.chat.id;
          const fromId = upd.message.from.id;
          const text = upd.message.text.trim();
          if(text.startsWith('/start')){
            if(!tgSessions[fromId] || !tgSessions[fromId].authed){
              await sendMessage(chatId, "Welcome. Please login with /login username password");
            }else{
              const menu = `🔹 Menu 🔹\\nChoose category:\\n1. Numbers (add/del/list)\\n2. Users\\n3. Admins\\n4. Resellers\\n\\nUse commands like /sudo addnumber`;
              await sendMessageWithPhoto(chatId, menu, null);
            }
          }else if(text.startsWith('/login')){
            const parts = text.split(' ').filter(Boolean);
            if(parts.length<3){ await sendMessage(chatId, "Usage: /login username password"); continue; }
            const username = parts[1], password = parts[2];
            const usr = usersDb.users.find(u=>u.username===username);
            if(!usr){ await sendMessage(chatId, "Invalid credentials"); logFailedLogin(username, fromId); continue; }
            if(!bcrypt.compareSync(password, usr.passwordHash)){ await sendMessage(chatId, "Invalid credentials"); logFailedLogin(username, fromId); continue; }
            tgSessions[fromId] = { username, role: usr.role, authed: true };
            await sendMessage(chatId, `Logged in as ${username} (${usr.role}). Use /menu to see options.`);
          }else if(text.startsWith('/menu')){
            if(!tgSessions[fromId] || !tgSessions[fromId].authed){ await sendMessage(chatId, "Please /login first"); continue; }
            const role = tgSessions[fromId].role;
            const menu = buildMenuForRole(role);
            await sendMessage(chatId, menu);
          }else if(text.startsWith('/sudo')){
            const parts = text.split(' ').filter(Boolean);
            if(parts.length<2){ await sendMessage(chatId, "Usage: /sudo [action] - you'll be prompted for password"); continue; }
            const action = parts.slice(1).join(' ');
            pending[fromId] = { action };
            await sendMessage(chatId, "Please reply with your password to confirm for sudo action.");
          }else if(pending[fromId] && text){
            const pwd = text;
            const sess = tgSessions[fromId];
            if(!sess || !sess.authed){ await sendMessage(chatId, "Session expired, please /login"); delete pending[fromId]; continue; }
            const usr = usersDb.users.find(u=>u.username===sess.username);
            if(!usr || !bcrypt.compareSync(pwd, usr.passwordHash)){ await sendMessage(chatId, "Wrong password"); logFailedLogin(sess.username, fromId); delete pending[fromId]; continue; }
            const act = pending[fromId].action;
            delete pending[fromId];
            await handleSudoAction(chatId, fromId, sess.username, sess.role, act);
          }
        }
      }
    }catch(e){
      console.warn("Bot error:", e.message);
    }finally{
      setTimeout(pollTelegram, 500);
    }
  }

  function buildMenuForRole(role){
    const base = ["• Add Number", "• Del Number", "• List Number"];
    if(role === 'admin'){
      base.push("• Add User", "• Del User", "• List User", "• Add Admin", "• Del Admin", "• List Admin");
    }
    if(role === 'reseller' || role === 'admin'){
      base.push("• Reseller Add/Del");
    }
    return "Menu ("+role+"):\\n" + base.join("\\n");
  }

  async function handleSudoAction(chatId, fromId, username, role, act){
    const parts = act.split(' ').filter(Boolean);
    const cmd = parts[0];
    if(cmd === 'addnumber'){
      const number = parts[1];
      if(!number || !/^\d+$/.test(number)){ await sendMessage(chatId, "Invalid number"); return; }
      if(!['admin','reseller'].includes(role)){ await sendMessage(chatId, "Permission denied"); return; }
      const nums = await fetchNumbersRaw();
      if(nums.includes(number)){ await sendMessage(chatId, "Already exists"); return; }
      nums.push(number);
      try{ await updateNumbersOnGithub(nums); await sendMessage(chatId, "Number added"); notifyAdmins(`[BOT] ${username} added ${number}`); }catch(e){ await sendMessage(chatId, "Failed to update"); }
    }else if(cmd === 'delnumber'){
      const number = parts[1];
      const nums = await fetchNumbersRaw();
      const idx = nums.indexOf(number);
      if(idx===-1){ await sendMessage(chatId, "Not found"); return; }
      nums.splice(idx,1);
      try{ await updateNumbersOnGithub(nums); await sendMessage(chatId, "Deleted"); notifyAdmins(`[BOT] ${username} deleted ${number}`); }catch(e){ await sendMessage(chatId, "Failed to update"); }
    }else if(cmd === 'listnumbers'){
      const nums = await fetchNumbersRaw();
      await sendMessage(chatId, "Numbers:\\n" + nums.join("\\n"));
    }else{
      await sendMessage(chatId, "Unknown action");
    }
  }

  async function sendMessage(chatId, text){
    try{ await axios.post(`https://api.telegram.org/bot${TELE_BOT}/sendMessage`, { chat_id: chatId, text }); }catch(e){}
  }

  async function sendMessageWithPhoto(chatId, text, photoUrl){
    try{
      if(photoUrl){
        await axios.post(`https://api.telegram.org/bot${TELE_BOT}/sendPhoto`, { chat_id: chatId, photo: photoUrl, caption: text });
      }else{
        await sendMessage(chatId, text);
      }
    }catch(e){}
  }

  function notifyAdmins(text){
    if(Array.isArray(settings.ADMINS)){
      settings.ADMINS.forEach(id => {
        axios.post(`https://api.telegram.org/bot${TELE_BOT}/sendMessage`, { chat_id: id, text }).catch(()=>{});
      });
    }
  }

  function logFailedLogin(username, tgId){
    const fl = safeLoadJson(FAILED_LOG, {failed: []});
    fl.failed.push({username, tgId, time: new Date().toISOString()});
    fs.writeFileSync(FAILED_LOG, JSON.stringify(fl,null,2));
  }

  pollTelegram();
}
