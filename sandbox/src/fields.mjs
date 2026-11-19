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
export function merge(old,value) {
  if(!object(value)||!object(old))return value;
  return Object.fromEntries([...new Set([...Object.keys(old),...Object.keys(value)])].map(k=>[k,Object.hasOwn(value,k)?merge(old[k],value[k]):old[k]]));
}
