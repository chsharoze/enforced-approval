import { fields, identifiers, leaves, merge } from './fields.mjs';
import { object } from './json.mjs';
import { DatabaseSync } from 'node:sqlite';
export class Sor {
  constructor(path) {
    this.db = new DatabaseSync(path); this.hooks = new Map();
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS property_definitions(object_type TEXT,path TEXT,PRIMARY KEY(object_type,path));
      CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS records(account TEXT, id TEXT, type TEXT, properties TEXT, version INTEGER, PRIMARY KEY(account,id));
      CREATE TABLE IF NOT EXISTS permissions(account TEXT, principal TEXT, operation TEXT, can_read INTEGER, can_write INTEGER, PRIMARY KEY(account,principal,operation));
      CREATE TABLE IF NOT EXISTS field_permissions(account TEXT,principal TEXT,operation TEXT,field TEXT,allowed INTEGER,PRIMARY KEY(account,principal,operation,field));
      CREATE TABLE IF NOT EXISTS members(account TEXT,person TEXT,allowed INTEGER,PRIMARY KEY(account,person));
      CREATE TABLE IF NOT EXISTS record_permissions(account TEXT,person TEXT,record TEXT,can_read INTEGER,can_write INTEGER,PRIMARY KEY(account,person,record));
      CREATE TABLE IF NOT EXISTS read_fields(account TEXT,principal TEXT,operation TEXT,field TEXT,allowed INTEGER,PRIMARY KEY(account,principal,operation,field));
      CREATE TABLE IF NOT EXISTS history(seq INTEGER PRIMARY KEY, account TEXT, record TEXT, action TEXT, properties TEXT);`);
    for(const type of ['contact','company'])for(const path of ['owner','lifecycle_stage','notes','email','phone','company','name','group','extra','uncovered','markup-field','/owner/id','/profile','/profile/name','/profile/email','/profile/secret'])this.defineProperty(type,path);
    for(const path of ['name','amount','closed','note'])this.defineProperty('deal',path);
  }
  defineProperty(type,path) {this.db.prepare('INSERT OR IGNORE INTO property_definitions VALUES(?,?)').run(type,path.startsWith('/')?path:'/'+path.replaceAll('~','~0').replaceAll('/','~1'));}
  defined(type,properties) {
    if(process.env.VA_MUTATE==='grant-on-undefined-property')return true;
    return object(properties)&&leaves(properties).every(path=>!!this.db.prepare('SELECT 1 FROM property_definitions WHERE object_type=? AND path=?').get(type??'contact',path));
  }
  undefinedProperties(type,properties) {return object(properties)?leaves(properties).filter(path=>!this.db.prepare('SELECT 1 FROM property_definitions WHERE object_type=? AND path=?').get(type??'contact',path)):[];}
  validateProperties(type,properties) {if(!object(properties))throw Error('invalid_input');const bad=this.undefinedProperties(type,properties);if(bad.length)throw Object.assign(Error('invalid_input'),{invalid:bad});}
  permission(account, principal, operation, read = true, write = true) { this.db.prepare('INSERT OR IGNORE INTO members VALUES(?,?,1)').run(account,principal);this.db.prepare('INSERT OR REPLACE INTO permissions VALUES(?,?,?,?,?)').run(account, principal, operation, +read, +write); }
  can(account, principal, operation, kind = 'write') { return !!this.db.prepare('SELECT * FROM permissions WHERE account=? AND principal=? AND operation=?').get(account, principal, operation)?.['can_' + kind]; }
  member(account,person,allowed=true) {this.db.prepare('INSERT OR REPLACE INTO members VALUES(?,?,?)').run(account,person,+allowed);}
  belongs(account,person) {return this.db.prepare('SELECT allowed FROM members WHERE account=? AND person=?').get(account,person)?.allowed===1;}
  recordPermission(account,person,record,read=true,write=true) {this.db.prepare('INSERT OR REPLACE INTO record_permissions VALUES(?,?,?,?,?)').run(account,person,record,+read,+write);}
  fieldPermission(account,principal,operation,field,allowed,kind='write') {this.db.prepare('INSERT OR REPLACE INTO '+(kind==='read'?'read_fields':'field_permissions')+' VALUES(?,?,?,?,?)').run(account,principal,operation,field,+allowed);}
  canFields(account,principal,operation,names,kind='write') {
    const denied=this.db.prepare('SELECT field FROM '+(kind==='read'?'read_fields':'field_permissions')+' WHERE account=? AND principal=? AND operation=? AND allowed=0').all(account,principal,operation).map(r=>r.field.startsWith('/')?r.field:'/'+r.field.replaceAll('~','~0').replaceAll('/','~1'));
    return this.can(account,principal,operation,kind)&&names.every(name=>!denied.some(d=>(name.startsWith('/')?name:'/'+name)===d||name.startsWith(d+'/')||d.startsWith((name.startsWith('/')?name:'/'+name)+'/')));
  }
  authorized(change,person,records,kind='write',current={}) {
    const names=[...fields(change),...(kind==='read'?[...leaves(change.arguments.filter??{}),...Object.values(current??{}).flatMap(v=>leaves(v))]:[])];
    return this.belongs(change.account,person)&&this.canFields(change.account,person,change.operation,names,kind)&&identifiers(change,records).every(id=>this.db.prepare('SELECT * FROM record_permissions WHERE account=? AND person=? AND record=?').get(change.account,person,id)?.['can_'+kind]!==0);
  }
  seed(account, id, properties = {}, type = 'contact') { this.db.prepare('INSERT OR IGNORE INTO accounts VALUES(?)').run(account); this.db.prepare('INSERT OR REPLACE INTO records VALUES(?,?,?,?,1)').run(account, id, type, JSON.stringify(properties)); }
  get(account, id) { const r = this.db.prepare('SELECT * FROM records WHERE account=? AND id=?').get(account, id); return r && { ...r, properties: JSON.parse(r.properties) }; }
  query(account, type, filter = {}) { return this.db.prepare('SELECT id FROM records WHERE account=? AND type=? ORDER BY id').all(account, type).map(r => this.get(account, r.id)).filter(r => Object.entries(filter).every(([k,v]) => r.properties[k] === v)).map(r => r.id).sort(); }
  inject(point, fn) { this.hooks.set(point, fn); }
  hit(point, context) { const fn = this.hooks.get(point); if (fn) { this.hooks.delete(point); fn(context); } }
  count() { return this.db.prepare('SELECT count(*) n FROM history').get().n; }
  write(account, entries, action, type, versions = {}) {
    for(const entry of entries)this.validateProperties(type,entry.properties??{});
    this.hit('before-write', { account, entries }); let n = 0;
    for (const entry of entries) {
      this.hit('before-record:' + entry.id, entry);
      const old = this.get(account, entry.id); const version = versions[entry.id];
      if ((action === 'create' && old) || (action !== 'create' && !old) || (version !== undefined && old?.version !== version)) throw Error('conflict');
      this.db.exec('BEGIN IMMEDIATE');
      try {
        if (action === 'create') this.db.prepare('INSERT INTO records VALUES(?,?,?,?,1)').run(account, entry.id, type, JSON.stringify(entry.properties));
        else if (action === 'delete') {
          if (!this.db.prepare('DELETE FROM records WHERE account=? AND id=? AND version=?').run(account, entry.id, old.version).changes) throw Error('conflict');
        } else {
          const props = merge(old.properties,entry.properties);
          if (!this.db.prepare('UPDATE records SET properties=?,version=version+1 WHERE account=? AND id=? AND version=?').run(JSON.stringify(props), account, entry.id, old.version).changes) throw Error('conflict');
          versions[entry.id] = old.version + 1; // duplicate entries count and execute separately
        }
        this.db.prepare('INSERT INTO history(account,record,action,properties) VALUES(?,?,?,?)').run(account, entry.id, action, JSON.stringify(entry.properties ?? {}));
        this.db.exec('COMMIT'); n++;
      } catch (e) { this.db.exec('ROLLBACK'); throw e; }
    }
    this.hit('after-write', { n }); return { changed: n };
  }
  close() { this.db.close(); }
}
