import { object } from './json.mjs';
const part=s=>s.replaceAll('~','~0').replaceAll('/','~1');
export function leaves(value,path='') {
  if(object(value)&&Object.keys(value).length)return Object.entries(value).flatMap(([key,v])=>leaves(v,path+'/'+part(key))).sort();
  return path?[path]:[];
}
export function hasArray(value) {return Array.isArray(value)||(object(value)&&Object.values(value).some(hasArray));}
export function fields(change) {
  const a=change.arguments;return [...new Set((a.records??[{properties:a.set??a.properties??{}}]).flatMap(r=>leaves(r.properties??{})))].sort();
}
export function identifiers(change,resolved) {return [...new Set(resolved??(change.arguments.records??[{id:change.arguments.id}]).map(r=>r.id))].filter(id=>typeof id==='string').sort();}
// S61/S60(a): the record's current value at each leaf the request sets (null if
// unset), and at nothing else. The walk mirrors leaves(): an object with members is
// descended into, anything else is a leaf, so a sibling leaf the request does not set
// (and the principal may not read) never enters the state hash or the stored values.
export function currentAt(old,set) {
  return Object.fromEntries(Object.entries(set??{}).map(([key,v])=>{
    const cur=object(old)&&Object.hasOwn(old,key)?old[key]:undefined;
    return [key,object(v)&&Object.keys(v).length?currentAt(cur,v):cur??null];
  }));
}
// S67/S53/S22: a covered copy names its target and only refers to its source, whose
// owner it reads. One place says which record and field that is, for the reader
// decision, the approver's permission checks and the page.
export function copySource(change) {
  const a=change?.arguments;
  return /:copy_record_owner$/.test(change?.operation??'')&&object(a)&&typeof a.source==='string'?{record:a.source,target:a.target,fields:['/owner']}:null;
}
// S67: "`arguments` as Section 5 of the core defines it before any value derived from
// record state is copied in." One place names the members a covered operation copies in
// from record state, so the request key, the S69(4) sibling comparison and the page all
// take the request's own arguments, never a copied value.
export function derivedMembers(operation) {return /:copy_record_owner$/.test(operation??'')?['copied_owner']:[];}
export function requestArguments(change) {
  const a=structuredClone(change?.arguments??{});
  for(const name of derivedMembers(change?.operation))delete a[name];
  return a;
}
export function merge(old,value) {
  if(!object(value)||!object(old))return value;
  return Object.fromEntries([...new Set([...Object.keys(old),...Object.keys(value)])].map(k=>[k,Object.hasOwn(value,k)?merge(old[k],value[k]):old[k]]));
}
