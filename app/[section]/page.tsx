import { notFound } from 'next/navigation';
export default async function Section({params}:{params:Promise<{section:string}>}){const {section}=await params;if(!['endpoints','threats','mitigation','intelligence','logs','administration'].includes(section))notFound();return null}
