const crypto=require('crypto');
function hashPassword(password,salt=crypto.randomBytes(16).toString('hex')){const hash=crypto.pbkdf2Sync(String(password),salt,120000,32,'sha256').toString('hex');return `${salt}:${hash}`}
function verifyPassword(password,stored){try{const [salt,hash]=String(stored).split(':');const actual=crypto.pbkdf2Sync(String(password),salt,120000,32,'sha256').toString('hex');return crypto.timingSafeEqual(Buffer.from(hash,'hex'),Buffer.from(actual,'hex'))}catch{return false}}
module.exports={hashPassword,verifyPassword};
