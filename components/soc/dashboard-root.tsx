
'use client';
import {useState} from 'react';
import {usePathname} from 'next/navigation';
import {QueryClient,QueryClientProvider} from '@tanstack/react-query';
import {SocApp} from './soc-app';
import {LiveWorkspace} from './live-workspace';
export function DashboardRoot(){const [client]=useState(()=>new QueryClient({defaultOptions:{queries:{retry:false,staleTime:0}}}));const path=usePathname();return <QueryClientProvider client={client}>{path==='/live'?<LiveWorkspace/>:<SocApp/>}</QueryClientProvider>}
