import type { Metadata } from 'next';
import './globals.css';
import { DashboardRoot } from '@/components/soc/dashboard-root';
export const metadata: Metadata = {title:'Sentinel | Security Operations',description:'A Windows-first security operations frontend. Milestone 1 prototype with clearly labelled simulated data.',icons:{icon:'/favicon.svg'}};
export default function RootLayout({children}:Readonly<{children:React.ReactNode}>){return <html lang="en"><body><DashboardRoot/>{children}</body></html>}
