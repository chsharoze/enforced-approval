import { leaves, merge } from './fields.mjs';
import { object } from './json.mjs';
import { DatabaseSync } from 'node:sqlite';
export class Sor {
  constructor(path) {
    this.db = new DatabaseSync(path); this.hooks = new Map();
    // Draft 0.2 model: `conditional` true means the system of record itself refuses a
    // write whose record is missing, already exists, or was merged under another
    // identifier. False models a system that offers nothing, so the server must read
    // immediately before the write (S64, S78). `idempotent` true means it treats a
    // repeat keyed by the receipt identifier as the same write (S25).
    this.conditional = true; this.idempotent = false;
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS property_definitions(object_type TEXT,path TEXT,PRIMARY KEY(object_type,path));
      CREATE TABLE IF NOT EXISTS restricted_definitions(object_type TEXT,path TEXT,PRIMARY KEY(object_type,path));
      CREATE TABLE IF NOT EXISTS definition_readers(account TEXT,principal TEXT,PRIMARY KEY(account,principal));
      CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS records(account TEXT, id TEXT, type TEXT, properties TEXT, version INTEGER, PRIMARY KEY(account,id));
      CREATE TABLE IF NOT EXISTS resolutions(account TEXT, from_id TEXT, to_id TEXT, PRIMARY KEY(account,from_id));
      CREATE TABLE IF NOT EXISTS applied_writes(key TEXT PRIMARY KEY, json TEXT);
      CREATE TABLE IF NOT EXISTS permissions(account TEXT, principal TEXT, operation TEXT, can_read INTEGER, can_write INTEGER, PRIMARY KEY(account,principal,operation));
      CREATE TABLE IF NOT EXISTS field_permissions(account TEXT,principal TEXT,operation TEXT,field TEXT,allowed INTEGER,PRIMARY KEY(account,principal,operation,field));
      CREATE TABLE IF NOT EXISTS members(account TEXT,person TEXT,allowed INTEGER,PRIMARY KEY(account,person));
      CREATE TABLE IF NOT EXISTS record_permissions(account TEXT,person TEXT,record TEXT,can_read INTEGER,can_write INTEGER,PRIMARY KEY(account,person,record));
      CREATE TABLE IF NOT EXISTS write_scopes(account TEXT,principal TEXT,PRIMARY KEY(account,principal));
      CREATE TABLE IF NOT EXISTS read_fields(account TEXT,principal TEXT,operation TEXT,field TEXT,allowed INTEGER,PRIMARY KEY(account,principal,operation,field));
      CREATE TABLE IF NOT EXISTS history(seq INTEGER PRIMARY KEY, account TEXT, record TEXT, action TEXT, properties TEXT);`);
    for(const type of ['contact','company'])for(const path of ['owner','lifecycle_stage','notes','email','phone','company','name','group','extra','uncovered','markup-field','/owner/id','/profile','/profile/name','/profile/email','/profile/secret'])this.defineProperty(type,path);
    for(const path of ['name','amount','closed','note'])this.defineProperty('deal',path);
  }
  defineProperty(type,path,options={}) {const stored=path.startsWith('/')?path:'/'+path.replaceAll('~','~0').replaceAll('/','~1');this.db.prepare('INSERT OR IGNORE INTO property_definitions VALUES(?,?)').run(type??'contact',stored);if(options.restricted)this.db.prepare('INSERT OR REPLACE INTO restricted_definitions VALUES(?,?)').run(type??'contact',stored);}
  // S48/S65: a principal established to see every definition of the object type is told
  // what is undefined before approval; any other principal gets the validation deferred
  // until after consumption. A restricted definition is visible only to a reader marked
  // with seeDefinitions.
  seeDefinitions(account,principal) {this.db.prepare('INSERT OR REPLACE INTO definition_readers VALUES(?,?)').run(account,principal);}
  established(account,principal,type) {return !this.db.prepare('SELECT 1 FROM restricted_definitions WHERE object_type=? LIMIT 1').get(type??'contact')||!!this.db.prepare('SELECT 1 FROM definition_readers WHERE account=? AND principal=?').get(account,principal);}
  defined(type,properties) {
    if(process.env.VA_MUTATE==='grant-on-undefined-property')return true;
    return object(properties)&&leaves(properties).every(path=>!!this.db.prepare('SELECT 1 FROM property_definitions WHERE object_type=? AND path=?').get(type??'contact',path));
  }
  undefinedProperties(type,properties) {return object(properties)?leaves(properties).filter(path=>!this.db.prepare('SELECT 1 FROM property_definitions WHERE object_type=? AND path=?').get(type??'contact',path)):[];}
  validateProperties(type,properties) {if(!object(properties))throw Error('invalid_input');const bad=this.undefinedProperties(type,properties);if(bad.length)throw Object.assign(Error('invalid_input'),{invalid:bad,sorText:`The system of record rejected the write: ${type??'contact'} does not define ${bad.join(', ')} on the record.`});}
  // A permission value of null models a source that answers neither yes nor no: it is
  // treated as not permitted (S60, S76).
  permission(account, principal, operation, read = true, write = true) { this.db.prepare('INSERT OR IGNORE INTO members VALUES(?,?,1)').run(account,principal);this.db.prepare('INSERT OR REPLACE INTO permissions VALUES(?,?,?,?,?)').run(account, principal, operation, read===null?null:+read, write===null?null:+write); }
  can(account, principal, operation, kind = 'write') { return !!this.db.prepare('SELECT * FROM permissions WHERE account=? AND principal=? AND operation=?').get(account, principal, operation)?.['can_' + kind]; }
  // S62: where the version kind is used the answer depends on every field of the
  // record, so any read denial makes the principal a non-reader for that answer.
  hasReadDenials(account, principal, operation) { return !!this.db.prepare('SELECT 1 FROM read_fields WHERE account=? AND principal=? AND operation=? AND allowed=0 LIMIT 1').get(account, principal, operation); }
  // S60/S76: every field of an object type whose read the permission model denies this
  // principal. The list comes from the type's definitions, never from record values.
  deniedFields(account, principal, operation, type = 'contact') {
    return this.db.prepare('SELECT path FROM property_definitions WHERE object_type=? ORDER BY path').all(type ?? 'contact')
      .map(r => r.path)
      .filter(path => !this.canFields(account, principal, operation, [path], 'read'));
  }
  // Test hook (CONFORMANCE Setup): a count of reads against the system of record.
  reads() { return this.readCount ?? 0; }
  member(account,person,allowed=true) {this.db.prepare('INSERT OR REPLACE INTO members VALUES(?,?,?)').run(account,person,+allowed);}
  belongs(account,person) {return this.db.prepare('SELECT allowed FROM members WHERE account=? AND person=?').get(account,person)?.allowed===1;}
  recordPermission(account,person,record,read=true,write=true) {this.db.prepare('INSERT OR REPLACE INTO record_permissions VALUES(?,?,?,?,?)').run(account,person,record,+read,+write);}
  // S60(c): a principal whose write permission is scoped by record. An update, a delete
  // or an association on a record outside the scope, or on a missing record, is refused
  // at step 1; a create is not.
  recordWriteScope(account,principal) {this.db.prepare('INSERT OR REPLACE INTO write_scopes VALUES(?,?)').run(account,principal);}
  writeScoped(account,principal) {return !!this.db.prepare('SELECT 1 FROM write_scopes WHERE account=? AND principal=?').get(account,principal);}
  mayWriteRecord(account,principal,record) {return this.db.prepare('SELECT can_write FROM record_permissions WHERE account=? AND person=? AND record=?').get(account,principal,record)?.can_write===1;}
  mayReadRecord(account,principal,record) {return this.db.prepare('SELECT can_read FROM record_permissions WHERE account=? AND person=? AND record=?').get(account,principal,record)?.can_read!==0;}
  fieldPermission(account,principal,operation,field,allowed,kind='write') {this.db.prepare('INSERT OR REPLACE INTO '+(kind==='read'?'read_fields':'field_permissions')+' VALUES(?,?,?,?,?)').run(account,principal,operation,field,+allowed);}
  canFields(account,principal,operation,names,kind='write') {
    const denied=this.db.prepare('SELECT field FROM '+(kind==='read'?'read_fields':'field_permissions')+' WHERE account=? AND principal=? AND operation=? AND allowed=0').all(account,principal,operation).map(r=>r.field.startsWith('/')?r.field:'/'+r.field.replaceAll('~','~0').replaceAll('/','~1'));
    return this.can(account,principal,operation,kind)&&names.every(name=>!denied.some(d=>(name.startsWith('/')?name:'/'+name)===d||name.startsWith(d+'/')||d.startsWith((name.startsWith('/')?name:'/'+name)+'/')));
  }
  // S72: an update by query's domain is the configured object type in the account.
  // Permission metadata must affirm every evaluated and written field and record in that
  // domain; this model cannot affirm a whole domain when any record-scoped read denial
  // exists. No record contents or query result participate in this answer.
  mayReadDomain(account,principal,operation,names) {
    return this.canFields(account,principal,operation,names,'read') &&
      !this.db.prepare('SELECT 1 FROM record_permissions WHERE account=? AND person=? AND can_read=0 LIMIT 1').get(account,principal);
  }
  // The permission rows above are the low-level source. Every decision made from them is
  // made by authorize() in src/authorize.mjs and nowhere else (milestone 1, WP1); the
  // person decision that used to live here (`authorized`) moved there.
  recordRow(account,subject,record) {return this.db.prepare('SELECT can_read,can_write FROM record_permissions WHERE account=? AND person=? AND record=?').get(account,subject,record);}
  // Whether the model holds any answer about this subject in the account (S76).
  knows(account,subject) {return !!this.db.prepare('SELECT 1 FROM members WHERE account=? AND person=?').get(account,subject);}
  seed(account, id, properties = {}, type = 'contact') { this.db.prepare('INSERT OR IGNORE INTO accounts VALUES(?)').run(account); this.db.prepare('INSERT OR REPLACE INTO records VALUES(?,?,?,?,1)').run(account, id, type, JSON.stringify(properties)); }
  // S78: an identifier can resolve to a record with another identifier, as after a
  // merge. The merged-from record is gone, so reads of the named record return the
  // record it resolves to, carrying the identifier it resolves to; the canonical form
  // of an identifier is its exact string.
  merge(account, from, to) { this.db.prepare('DELETE FROM records WHERE account=? AND id=?').run(account, from); this.db.prepare('INSERT OR REPLACE INTO resolutions VALUES(?,?,?)').run(account, from, to); }
  unmerged(account, from) { this.db.prepare('DELETE FROM resolutions WHERE account=? AND from_id=?').run(account, from); }
  resolveId(account, id) { for (let i = 0; i < 32; i++) { const r = this.db.prepare('SELECT to_id FROM resolutions WHERE account=? AND from_id=?').get(account, id); if (!r) return id; id = r.to_id; } return id; }
  // S60(i): a read of record state that does not complete — an ordinary error or a
  // timeout, with or without a code — is approval_unavailable; nothing it gated is
  // consumed, closed or superseded.
  get(account, id) {
    try {
      this.readCount = (this.readCount ?? 0) + 1;
      this.hit('before-get', { account, id });
      const target = this.resolveId(account, id); const r = this.db.prepare('SELECT * FROM records WHERE account=? AND id=?').get(account, target);
      return r && { ...r, id: target, properties: JSON.parse(r.properties) };
    } catch (e) { e.code ??= 'approval_unavailable'; throw e; }
  }
  query(account, type, filter = {}) { return this.db.prepare('SELECT id FROM records WHERE account=? AND type=? ORDER BY id').all(account, type).map(r => r.id).filter(id => Object.entries(filter).every(([k,v]) => this.get(account, id)?.properties[k] === v)).sort(); }
  inject(point, fn) { this.hooks.set(point, fn); }
  hit(point, context) { const fn = this.hooks.get(point); if (fn) { this.hooks.delete(point); fn(context); } }
  count() { return this.db.prepare('SELECT count(*) n FROM history').get().n; }
  write(account, entries, action, type, versions = {}, options = {}) {
    // S65: an entry's properties, when the entry has them, must be an object; a null
    // value must not reach the store and erase the record's fields.
    for(const entry of entries)if(entry.properties!==undefined)this.validateProperties(type,entry.properties);
    // S25: where the system of record treats a repeat as the same write, keyed by the
    // receipt identifier, a keyed repeat returns the recorded answer of the first write.
    if (options.key !== undefined) { const prior = this.db.prepare('SELECT json FROM applied_writes WHERE key=?').get(options.key); if (prior) return JSON.parse(prior.json); }
    this.hit('before-write', { account, entries }); let n = 0;
    const applied = [], stored = [];
    // S17, S77: the store is capable of writing one entry and then failing
    // another, as a real one is. A batch that partly succeeded is not rolled back as a
    // whole: the entries already written stay written, and the failure names the entry it
    // happened on so the caller can report each entry's outcome. A single-entry write
    // behaves as before (it either writes or does not).
    for (let index = 0; index < entries.length; index++) {
      const entry = entries[index];
      // A failed entry after a written one is the partial outcome. The failed entry's own
      // transaction rolls back; the written entries' transactions already committed.
      try {
        this.hit('before-record:' + entry.id, entry);
        const target = this.resolveId(account, entry.id);
        const old = this.get(account, entry.id);
        if (this.conditional) {
          if ((action === 'create' && old) || (action !== 'create' && !old) || (versions[entry.id] !== undefined && old?.version !== versions[entry.id]))
            throw Object.assign(Error('conflict'), { sorText: `The system of record rejected the write to ${entry.id}: it currently holds ${JSON.stringify(old?.properties ?? null)}.` });
        }
        this.db.exec('BEGIN IMMEDIATE');
        const where = this.conditional ? entry.id : target;
        if (action === 'create') this.db.prepare(this.conditional ? 'INSERT INTO records VALUES(?,?,?,?,1)' : 'INSERT OR REPLACE INTO records VALUES(?,?,?,?,1)').run(account, where, type, JSON.stringify(entry.properties));
        else if (action === 'delete') {
          if (this.conditional) { if (!this.db.prepare('DELETE FROM records WHERE account=? AND id=? AND version=?').run(account, where, old.version).changes) throw Error('conflict'); }
          else this.db.prepare('DELETE FROM records WHERE account=? AND id=?').run(account, where);
        } else {
          const current = this.conditional ? old.properties : (this.get(account, target)?.properties ?? {});
          const changed = this.db.prepare('UPDATE records SET properties=?,version=version+1 WHERE account=? AND id=?' + (this.conditional ? ' AND version=?' : '')).run(JSON.stringify(merge(current, entry.properties)), account, where, ...(this.conditional ? [old.version] : [])).changes;
          if (this.conditional && !changed) throw Error('conflict');
          versions[entry.id] = (this.conditional ? old.version : (this.get(account, target)?.version ?? 1)) + 1; // duplicate entries count and execute separately
        }
        this.db.prepare('INSERT INTO history(account,record,action,properties) VALUES(?,?,?,?)').run(account, entry.id, action, JSON.stringify(entry.properties ?? {}));
        // S77: whether this write created the record. A create writes a record that was
        // absent; an update, a delete, or a create the store applies to an identifier that
        // already holds a record did not create the one it changed.
        this.db.exec('COMMIT'); n++; applied.push({ id: entry.id, to: target, created: action === 'create' && !old }); stored.push(this.get(account, target));
      } catch (e) {
        if (this.db.isTransaction) this.db.exec('ROLLBACK');
        if (!n) throw e; // nothing succeeded: the whole write fails as it always did
        // Some entries succeeded. The failure is returned with what was written, and each
        // later entry is not sent (S77: not_sent).
        e.partial = { applied: [...applied], stored: [...stored], notSent: entries.slice(index + 1).map(x => x.id), failedEntry: entry.id };
        throw e;
      }
    }
    // A system of record returns record content and its own text on a write (S77).
    const out = { changed: n, applied, stored, sorText: 'The system of record accepted the write.' };
    if (options.key !== undefined) this.db.prepare('INSERT OR REPLACE INTO applied_writes VALUES(?,?)').run(options.key, JSON.stringify(out));
    try { this.hit('after-write', { n }); } catch (e) { e.lost = true; throw e; }
    return out;
  }
  close() { this.db.close(); }
}
